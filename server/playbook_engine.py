import json
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from server.database import Base
from server.incident_engine import SecurityIncident, get_incident


PLAYBOOK_STATUS = {
    "PENDING",
    "IN_PROGRESS",
    "CONTAINED",
    "COMPLETED"
}

STEP_STATUS = {
    "PENDING",
    "APPROVED",
    "COMPLETED",
    "SKIPPED"
}


class ResponsePlaybookExecution(Base):
    __tablename__ = "response_playbook_executions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(
        Integer,
        ForeignKey("security_incidents.id"),
        unique=True,
        index=True,
        nullable=False
    )
    playbook_key = Column(String, nullable=False)
    playbook_name = Column(String, nullable=False)
    status = Column(String, default="PENDING", nullable=False)
    steps_json = Column(Text, default="[]", nullable=False)
    history_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.now,
        onupdate=datetime.now,
        nullable=False
    )


def _now_text():
    return datetime.now().isoformat(timespec="seconds")


def _base_step(
    step_id,
    title,
    description,
    action_type,
    approval_required=False,
    containment=False
):
    return {
        "step_id": step_id,
        "title": title,
        "description": description,
        "action_type": action_type,
        "approval_required": approval_required,
        "containment": containment,
        "automated": False,
        "status": "PENDING",
        "approved_at": None,
        "completed_at": None,
        "note": None
    }


def _account_exfiltration_steps():
    return [
        _base_step(
            "PB-01",
            "계정 활동 검증",
            "로그인 실패·성공 시각, 출발지 IP, 사용자 정상 근무 패턴을 확인합니다.",
            "INVESTIGATE"
        ),
        _base_step(
            "PB-02",
            "의심 계정 잠금 검토",
            "계정 탈취 가능성이 충분한지 검토한 뒤 계정 잠금 필요 여부를 결정합니다.",
            "ACCOUNT_LOCK_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-03",
            "활성 세션 격리 검토",
            "의심 세션의 추가 활동을 제한할 필요가 있는지 검토합니다.",
            "SESSION_ISOLATION_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-04",
            "민감정보 추가 접근 제한 검토",
            "관련 계정의 대외비·민감 문서 추가 접근을 제한할 필요가 있는지 검토합니다.",
            "SENSITIVE_ACCESS_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-05",
            "USB 장치 및 반출 여부 조사",
            "USB 식별정보와 파일 복사 흔적을 확인하여 실제 반출 여부를 조사합니다.",
            "USB_INVESTIGATION"
        ),
        _base_step(
            "PB-06",
            "관련 로그 및 증거 보존",
            "Incident 관련 이벤트 ID, 시간, 사용자, 파일, 프로세스 증거를 보존 대상으로 기록합니다.",
            "PRESERVE_EVIDENCE"
        ),
        _base_step(
            "PB-07",
            "SOC 분석가 상세 조사",
            "AI SOC Analyst 결과와 원본 로그를 함께 검토하여 미확인 사항을 조사합니다.",
            "ANALYST_INVESTIGATION"
        ),
        _base_step(
            "PB-08",
            "사고 종결 검토",
            "조사 및 필요한 대응이 완료되었는지 확인한 뒤 사고 종결을 검토합니다.",
            "CLOSE_REVIEW",
            approval_required=True
        )
    ]


def _account_compromise_steps():
    return [
        _base_step(
            "PB-01",
            "계정 활동 검증",
            "로그인 실패·성공 시각과 출발지 IP를 확인합니다.",
            "INVESTIGATE"
        ),
        _base_step(
            "PB-02",
            "의심 계정 잠금 검토",
            "계정 탈취 가능성을 검토하고 계정 잠금 필요 여부를 결정합니다.",
            "ACCOUNT_LOCK_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-03",
            "활성 세션 격리 검토",
            "의심 세션 제한 필요 여부를 검토합니다.",
            "SESSION_ISOLATION_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-04",
            "인증정보 변경 검토",
            "비밀번호 재설정 및 추가 인증 조치 필요 여부를 검토합니다.",
            "CREDENTIAL_RESET_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-05",
            "관련 로그 및 증거 보존",
            "계정 침해 판단에 필요한 로그를 보존 대상으로 기록합니다.",
            "PRESERVE_EVIDENCE"
        ),
        _base_step(
            "PB-06",
            "SOC 분석가 상세 조사",
            "원본 이벤트와 ATT&CK 매핑을 검토합니다.",
            "ANALYST_INVESTIGATION"
        ),
        _base_step(
            "PB-07",
            "사고 종결 검토",
            "조사 및 필요한 대응 완료 여부를 확인합니다.",
            "CLOSE_REVIEW",
            approval_required=True
        )
    ]


def _data_exfiltration_steps():
    return [
        _base_step(
            "PB-01",
            "민감정보 접근 범위 확인",
            "접근한 파일과 접근량, 파일 등급을 확인합니다.",
            "INVESTIGATE"
        ),
        _base_step(
            "PB-02",
            "추가 민감정보 접근 제한 검토",
            "추가 접근을 제한할 필요가 있는지 검토합니다.",
            "SENSITIVE_ACCESS_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-03",
            "USB 및 외부 전송 흔적 조사",
            "실제 파일 복사 또는 외부 전송 증거가 존재하는지 조사합니다.",
            "EXFILTRATION_INVESTIGATION"
        ),
        _base_step(
            "PB-04",
            "관련 로그 및 증거 보존",
            "파일·USB·프로세스 관련 증거를 보존 대상으로 기록합니다.",
            "PRESERVE_EVIDENCE"
        ),
        _base_step(
            "PB-05",
            "SOC 분석가 상세 조사",
            "AI 분석과 원본 로그를 함께 검토합니다.",
            "ANALYST_INVESTIGATION"
        ),
        _base_step(
            "PB-06",
            "사고 종결 검토",
            "조사 및 필요한 대응 완료 여부를 확인합니다.",
            "CLOSE_REVIEW",
            approval_required=True
        )
    ]


def _generic_steps():
    return [
        _base_step(
            "PB-01",
            "의심 활동 검증",
            "Incident Storyline과 원본 이벤트를 확인합니다.",
            "INVESTIGATE"
        ),
        _base_step(
            "PB-02",
            "영향 범위 조사",
            "관련 사용자·파일·프로세스·IP의 영향을 조사합니다.",
            "SCOPE_INVESTIGATION"
        ),
        _base_step(
            "PB-03",
            "필요한 격리 조치 검토",
            "추가 피해 방지를 위한 제한 조치 필요 여부를 검토합니다.",
            "CONTAINMENT_REVIEW",
            approval_required=True,
            containment=True
        ),
        _base_step(
            "PB-04",
            "관련 로그 및 증거 보존",
            "Incident 관련 증거를 보존 대상으로 기록합니다.",
            "PRESERVE_EVIDENCE"
        ),
        _base_step(
            "PB-05",
            "사고 종결 검토",
            "조사 및 필요한 대응 완료 여부를 확인합니다.",
            "CLOSE_REVIEW",
            approval_required=True
        )
    ]


def _select_playbook(incident):
    incident_type = str(
        incident.get("incident_type") or ""
    ).upper()

    title = str(
        incident.get("title") or ""
    )

    if (
        "ACCOUNT_COMPROMISE_DATA_EXFILTRATION" in incident_type
        or (
            "계정" in title
            and "유출" in title
        )
    ):
        return (
            "ACCOUNT_COMPROMISE_DATA_EXFILTRATION",
            "계정 침해 및 정보 유출 대응",
            _account_exfiltration_steps()
        )

    if (
        "ACCOUNT_COMPROMISE" in incident_type
        or "계정 침해" in title
        or "계정 탈취" in title
    ):
        return (
            "ACCOUNT_COMPROMISE",
            "계정 침해 대응",
            _account_compromise_steps()
        )

    if (
        "DATA_EXFILTRATION" in incident_type
        or "정보 유출" in title
        or "반출" in title
    ):
        return (
            "DATA_EXFILTRATION",
            "정보 유출 대응",
            _data_exfiltration_steps()
        )

    return (
        "SUSPICIOUS_ACTIVITY",
        "의심 활동 조사",
        _generic_steps()
    )


def _safe_json_load(value, default):
    try:
        parsed = json.loads(value or "")
        return parsed
    except (TypeError, json.JSONDecodeError):
        return default


def _serialize_execution(execution):
    steps = _safe_json_load(execution.steps_json, [])
    history = _safe_json_load(execution.history_json, [])

    completed_count = sum(
        1
        for step in steps
        if step.get("status") in {"COMPLETED", "SKIPPED"}
    )

    approved_count = sum(
        1
        for step in steps
        if step.get("status") == "APPROVED"
    )

    total_count = len(steps)

    progress_percent = (
        round((completed_count / total_count) * 100, 1)
        if total_count
        else 0.0
    )

    return {
        "id": execution.id,
        "incident_id": execution.incident_id,
        "playbook_key": execution.playbook_key,
        "playbook_name": execution.playbook_name,
        "status": execution.status,
        "steps": steps,
        "history": history,
        "completed_step_count": completed_count,
        "approved_step_count": approved_count,
        "total_step_count": total_count,
        "progress_percent": progress_percent,
        "created_at": execution.created_at,
        "updated_at": execution.updated_at
    }


def _append_history(history, action, step=None, note=None):
    history.append({
        "timestamp": _now_text(),
        "action": action,
        "step_id": (
            step.get("step_id")
            if step
            else None
        ),
        "step_title": (
            step.get("title")
            if step
            else None
        ),
        "note": note
    })


def _refresh_execution_status(execution, steps):
    if steps and all(
        step.get("status") in {"COMPLETED", "SKIPPED"}
        for step in steps
    ):
        execution.status = "COMPLETED"
        return

    containment_steps = [
        step
        for step in steps
        if step.get("containment")
    ]

    if containment_steps and any(
        step.get("status") == "COMPLETED"
        for step in containment_steps
    ):
        execution.status = "CONTAINED"
        return

    if any(
        step.get("status") in {
            "APPROVED",
            "COMPLETED",
            "SKIPPED"
        }
        for step in steps
    ):
        execution.status = "IN_PROGRESS"
        return

    execution.status = "PENDING"


def get_or_create_playbook(
    db: Session,
    incident_id: int
):
    incident = get_incident(
        db=db,
        incident_id=incident_id
    )

    if incident is None:
        return None, "보안 사고를 찾을 수 없습니다."

    existing = (
        db.query(ResponsePlaybookExecution)
        .filter(
            ResponsePlaybookExecution.incident_id
            == incident_id
        )
        .first()
    )

    if existing:
        return _serialize_execution(existing), None

    playbook_key, playbook_name, steps = (
        _select_playbook(incident)
    )

    history = []
    _append_history(
        history,
        "PLAYBOOK_CREATED",
        note=(
            f"{incident.get('incident_type')} / "
            f"{incident.get('severity')} Incident에 따라 "
            f"'{playbook_name}' Playbook을 생성했습니다."
        )
    )

    execution = ResponsePlaybookExecution(
        incident_id=incident_id,
        playbook_key=playbook_key,
        playbook_name=playbook_name,
        status="PENDING",
        steps_json=json.dumps(
            steps,
            ensure_ascii=False
        ),
        history_json=json.dumps(
            history,
            ensure_ascii=False
        )
    )

    db.add(execution)
    db.commit()
    db.refresh(execution)

    return _serialize_execution(execution), None


def update_playbook_step(
    db: Session,
    incident_id: int,
    step_id: str,
    action: str,
    note=None
):
    execution = (
        db.query(ResponsePlaybookExecution)
        .filter(
            ResponsePlaybookExecution.incident_id
            == incident_id
        )
        .first()
    )

    if execution is None:
        _, error = get_or_create_playbook(
            db=db,
            incident_id=incident_id
        )

        if error:
            return None, error

        execution = (
            db.query(ResponsePlaybookExecution)
            .filter(
                ResponsePlaybookExecution.incident_id
                == incident_id
            )
            .first()
        )

    steps = _safe_json_load(
        execution.steps_json,
        []
    )

    history = _safe_json_load(
        execution.history_json,
        []
    )

    target = next(
        (
            step
            for step in steps
            if step.get("step_id") == step_id
        ),
        None
    )

    if target is None:
        return None, "Playbook 단계를 찾을 수 없습니다."

    normalized_action = str(action or "").upper()

    if normalized_action == "APPROVE":
        if not target.get("approval_required"):
            return None, "이 단계는 별도 승인이 필요하지 않습니다."

        if target.get("status") == "COMPLETED":
            return None, "이미 완료된 단계입니다."

        target["status"] = "APPROVED"
        target["approved_at"] = _now_text()
        target["note"] = note

        _append_history(
            history,
            "STEP_APPROVED",
            step=target,
            note=note
        )

    elif normalized_action == "COMPLETE":
        if (
            target.get("approval_required")
            and target.get("status") != "APPROVED"
        ):
            return None, "관리자 승인 후 처리 완료할 수 있습니다."

        if target.get("status") == "COMPLETED":
            return None, "이미 완료된 단계입니다."

        target["status"] = "COMPLETED"
        target["completed_at"] = _now_text()
        target["note"] = note

        _append_history(
            history,
            "STEP_COMPLETED",
            step=target,
            note=note
        )

    elif normalized_action == "SKIP":
        if target.get("status") == "COMPLETED":
            return None, "이미 완료된 단계입니다."

        target["status"] = "SKIPPED"
        target["completed_at"] = _now_text()
        target["note"] = note

        _append_history(
            history,
            "STEP_SKIPPED",
            step=target,
            note=note
        )

    else:
        return None, "지원하지 않는 Playbook 작업입니다."

    _refresh_execution_status(
        execution,
        steps
    )

    execution.steps_json = json.dumps(
        steps,
        ensure_ascii=False
    )
    execution.history_json = json.dumps(
        history,
        ensure_ascii=False
    )
    execution.updated_at = datetime.now()

    db.commit()
    db.refresh(execution)

    return _serialize_execution(execution), None
