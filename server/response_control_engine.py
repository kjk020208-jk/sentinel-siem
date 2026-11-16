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


VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT"}
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


def claim_next_action(db: Session, *, hostname: str):
    rows = (
        db.query(ResponseControlAction)
        .filter(ResponseControlAction.status == "QUEUED")
        .order_by(ResponseControlAction.id.asc())
        .limit(50)
        .all()
    )
    hostname_l = (hostname or "").lower()
    selected = None
    for row in rows:
        if not row.target_host or str(row.target_host).lower() == hostname_l:
            selected = row
            break
    if selected is None:
        return None
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
