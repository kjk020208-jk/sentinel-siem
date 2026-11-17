import json
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import Session

from server.database import Base


class ResponseControlAction(Base):
    __tablename__ = "response_control_actions"

    id = Column(Integer, primary_key=True, index=True)
    user = Column(String, index=True, nullable=False)
    target_host = Column(String, index=True, nullable=True)
    target_agent_id = Column(String, index=True, nullable=True)
    action_type = Column(String, index=True, nullable=False)
    operation = Column(String, nullable=False)
    status = Column(String, index=True, default="QUEUED", nullable=False)
    reason = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=True)
    threat_progress = Column(Integer, nullable=True)
    predicted_vector = Column(String, nullable=True)
    prediction_confidence = Column(Integer, nullable=True)
    requested_by = Column(String, nullable=True)
    user_justification = Column(Text, nullable=True)
    admin_note = Column(Text, nullable=True)
    agent_message = Column(Text, nullable=True)
    active_window = Column(Text, nullable=True)
    running_processes_json = Column(Text, default="[]", nullable=False)
    screenshot_path = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    claimed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)


VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT", "PROCESS_TERMINATE", "NETWORK_RESTRICT"}
VALID_OPERATIONS = {"APPLY", "RELEASE"}


def _serialize(row):
    if row is None:
        return None
    try:
        processes = json.loads(row.running_processes_json or "[]")
    except Exception:
        processes = []
    return {
        "id": row.id,
        "user": row.user,
        "target_host": row.target_host,
        "target_agent_id": row.target_agent_id,
        "action_type": row.action_type,
        "operation": row.operation,
        "status": row.status,
        "reason": row.reason,
        "risk_score": row.risk_score,
        "threat_progress": row.threat_progress,
        "predicted_vector": row.predicted_vector,
        "prediction_confidence": row.prediction_confidence,
        "requested_by": row.requested_by,
        "user_justification": row.user_justification,
        "admin_note": row.admin_note,
        "agent_message": row.agent_message,
        "active_window": row.active_window,
        "running_processes": processes,
        "screenshot_path": row.screenshot_path,
        "created_at": row.created_at,
        "claimed_at": row.claimed_at,
        "completed_at": row.completed_at,
        "updated_at": row.updated_at,
    }


def create_control_action(
    db: Session,
    *,
    user: str,
    action_type: str,
    operation: str,
    reason: Optional[str] = None,
    target_host: Optional[str] = None,
    target_agent_id: Optional[str] = None,
    risk_score: Optional[int] = None,
    threat_progress: Optional[int] = None,
    predicted_vector: Optional[str] = None,
    prediction_confidence: Optional[int] = None,
    requested_by: Optional[str] = None,
    user_justification: Optional[str] = None,
    admin_note: Optional[str] = None,
):
    action_type = str(action_type or "").upper().strip()
    operation = str(operation or "").upper().strip()

    if action_type not in VALID_ACTION_TYPES:
        return None, f"지원하지 않는 제어 유형입니다: {action_type}"
    if operation not in VALID_OPERATIONS:
        return None, f"지원하지 않는 작업입니다: {operation}"

    row = ResponseControlAction(
        user=user,
        target_host=target_host or None,
        target_agent_id=target_agent_id or None,
        action_type=action_type,
        operation=operation,
        status="QUEUED",
        reason=reason,
        risk_score=risk_score,
        threat_progress=threat_progress,
        predicted_vector=predicted_vector,
        prediction_confidence=prediction_confidence,
        requested_by=requested_by,
        user_justification=user_justification,
        admin_note=admin_note,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _serialize(row), None


def list_control_actions(db: Session, *, user=None, status=None, limit=100):
    q = db.query(ResponseControlAction)
    if user:
        q = q.filter(ResponseControlAction.user == user)
    if status:
        q = q.filter(ResponseControlAction.status == status.upper())
    safe_limit = max(1, min(int(limit or 100), 500))
    rows = q.order_by(ResponseControlAction.id.desc()).limit(safe_limit).all()
    return [_serialize(x) for x in rows]


def claim_next_action(
    db: Session,
    *,
    hostname: str,
    agent_id: Optional[str] = None,
):
    hostname_l = (hostname or "").lower().strip()
    agent_id_l = (agent_id or "").lower().strip()

    # 최신 QUEUED 작업부터 확인한다.
    # 예전에는 id ASC라서 오래된 중복 제어가 순차 실행되는 문제가 있었다.
    rows = (
        db.query(ResponseControlAction)
        .filter(ResponseControlAction.status == "QUEUED")
        .order_by(ResponseControlAction.id.desc())
        .limit(100)
        .all()
    )

    matching = []

    for row in rows:
        target_agent_id = str(
            getattr(row, "target_agent_id", None) or ""
        ).lower().strip()

        target_host = str(
            row.target_host or ""
        ).lower().strip()

        if target_agent_id:
            if agent_id_l and target_agent_id == agent_id_l:
                matching.append(row)
            continue

        if not target_host or target_host == hostname_l:
            matching.append(row)

    if not matching:
        return None

    # RELEASE가 있으면 같은 대상/제어유형의 APPLY보다 우선한다.
    # 사용자가 해제 승인을 받은 뒤 과거 APPLY가 다시 실행되는 것을 방지한다.
    release_rows = [
        row for row in matching
        if row.operation == "RELEASE"
    ]

    if release_rows:
        selected = max(
            release_rows,
            key=lambda row: row.id,
        )
    else:
        selected = max(
            matching,
            key=lambda row: row.id,
        )

    selected_action_type = str(
        selected.action_type or ""
    ).upper().strip()

    selected_target_host = str(
        selected.target_host or ""
    ).lower().strip()

    selected_target_agent_id = str(
        getattr(selected, "target_agent_id", None) or ""
    ).lower().strip()

    # 같은 대상 + 같은 제어 유형의 오래된 QUEUED 중복 작업은
    # 다시 실행되지 않도록 SUPERSEDED 처리한다.
    superseded = []

    for row in matching:
        if row.id == selected.id:
            continue

        row_action_type = str(
            row.action_type or ""
        ).upper().strip()

        row_target_host = str(
            row.target_host or ""
        ).lower().strip()

        row_target_agent_id = str(
            getattr(row, "target_agent_id", None) or ""
        ).lower().strip()

        same_action = (
            row_action_type == selected_action_type
        )

        same_target = False

        if selected_target_agent_id:
            same_target = (
                row_target_agent_id == selected_target_agent_id
            )
        elif selected_target_host:
            same_target = (
                row_target_host == selected_target_host
            )
        else:
            same_target = (
                not row_target_host
                and not row_target_agent_id
            )

        if same_action and same_target:
            row.status = "SUPERSEDED"
            row.completed_at = datetime.now()
            row.agent_message = (
                f"최신 제어 #{selected.id}에 의해 대체됨"
            )
            superseded.append(row.id)

    selected.status = "CLAIMED"
    selected.claimed_at = datetime.now()

    db.commit()
    db.refresh(selected)

    return _serialize(selected)

def complete_action(
    db: Session,
    *,
    action_id: int,
    success: bool,
    agent_message=None,
    active_window=None,
    running_processes=None,
    screenshot_path=None,
):
    row = db.query(ResponseControlAction).filter(ResponseControlAction.id == action_id).first()
    if row is None:
        return None, "제어 작업을 찾을 수 없습니다."
    row.status = "COMPLETED" if success else "FAILED"
    row.agent_message = agent_message
    row.active_window = active_window
    row.running_processes_json = json.dumps(running_processes or [], ensure_ascii=False)
    row.screenshot_path = screenshot_path
    row.completed_at = datetime.now()
    db.commit()
    db.refresh(row)
    return _serialize(row), None


def request_release(
    db: Session,
    *,
    action_id: int,
    justification: str,
    active_window=None,
    running_processes=None,
    screenshot_path=None,
):
    source = db.query(ResponseControlAction).filter(ResponseControlAction.id == action_id).first()
    if source is None:
        return None, "기존 제어 작업을 찾을 수 없습니다."
    if source.operation != "APPLY":
        return None, "APPLY 작업에 대해서만 해제 요청할 수 있습니다."

    row = ResponseControlAction(
        user=source.user,
        target_host=source.target_host,
        action_type=source.action_type,
        operation="RELEASE",
        status="AWAITING_ADMIN",
        reason=f"사용자 해제 요청 · 원본 제어 #{source.id}",
        risk_score=source.risk_score,
        threat_progress=source.threat_progress,
        predicted_vector=source.predicted_vector,
        prediction_confidence=source.prediction_confidence,
        requested_by="USER",
        user_justification=justification,
        active_window=active_window or source.active_window,
        running_processes_json=json.dumps(
            running_processes, ensure_ascii=False
        ) if running_processes else source.running_processes_json,
        screenshot_path=screenshot_path or source.screenshot_path,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _serialize(row), None


def decide_release_request(db: Session, *, request_id: int, decision: str, admin_note=None):
    row = db.query(ResponseControlAction).filter(ResponseControlAction.id == request_id).first()
    if row is None:
        return None, "해제 요청을 찾을 수 없습니다."
    if row.operation != "RELEASE":
        return None, "해제 요청이 아닙니다."
    if row.status != "AWAITING_ADMIN":
        return None, f"현재 상태에서는 결정할 수 없습니다: {row.status}"

    decision = str(decision or "").upper().strip()
    if decision == "APPROVE":
        row.status = "QUEUED"
        row.admin_note = admin_note
    elif decision == "REJECT":
        row.status = "REJECTED"
        row.admin_note = admin_note
        row.completed_at = datetime.now()
    else:
        return None, "decision은 APPROVE 또는 REJECT여야 합니다."

    db.commit()
    db.refresh(row)
    return _serialize(row), None

def migrate_response_control_agent_target(engine):
    from sqlalchemy import inspect, text

    inspector = inspect(engine)

    if "response_control_actions" not in inspector.get_table_names():
        return

    columns = {
        col["name"]
        for col in inspector.get_columns("response_control_actions")
    }

    if "target_agent_id" in columns:
        return

    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE response_control_actions "
                "ADD COLUMN target_agent_id VARCHAR"
            )
        )

    print("[DB MIGRATION] response_control_actions.target_agent_id added")

