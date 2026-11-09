from datetime import datetime, timedelta
import json

from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from sqlalchemy.orm import Session

from server.database import Base
from server.models import SecurityEvent


INCIDENT_WINDOW_MINUTES = 30

SUSPICIOUS_PROCESSES = {
    # Sequence Engine의 외부 전송 가능 프로세스와 의미를 맞춘다.
    "chrome.exe",
    "msedge.exe",
    "outlook.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "curl.exe",
    "bitsadmin.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "rar.exe",
    "7z.exe"
}


class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user = Column(
        String,
        index=True,
        nullable=False
    )

    incident_type = Column(
        String,
        nullable=False
    )

    title = Column(
        String,
        nullable=False
    )

    severity = Column(
        String,
        nullable=False
    )

    correlation_score = Column(
        Float,
        default=0,
        nullable=False
    )

    status = Column(
        String,
        default="OPEN",
        nullable=False
    )

    start_time = Column(
        DateTime,
        nullable=False
    )

    end_time = Column(
        DateTime,
        nullable=False
    )

    event_count = Column(
        Integer,
        default=0,
        nullable=False
    )

    event_ids_json = Column(
        Text,
        default="[]",
        nullable=False
    )

    stages_json = Column(
        Text,
        default="[]",
        nullable=False
    )

    storyline_json = Column(
        Text,
        default="[]",
        nullable=False
    )

    summary = Column(
        Text,
        default="",
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.now,
        nullable=False
    )

    updated_at = Column(
        DateTime,
        default=datetime.now,
        nullable=False
    )


def _severity(score):
    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


def _event_time(event):
    return event.timestamp or datetime.now()



MITRE_STAGE_MAPPING = {
    "CREDENTIAL_FAILURE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "HIGH"
    },
    "ACCOUNT_ACCESS": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access / Persistence / Privilege Escalation / Defense Evasion",
        "confidence": "MEDIUM"
    },
    "SENSITIVE_ACCESS": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "confidence": "MEDIUM"
    },
    "COLLECTION": {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "Collection",
        "confidence": "MEDIUM"
    },
    "REMOVABLE_MEDIA": {
        "technique_id": "T1052.001",
        "technique_name": "Exfiltration over USB",
        "tactic": "Exfiltration",
        "confidence": "LOW"
    }
}


def _get_mitre_mapping(stage_id, event):
    mapping = MITRE_STAGE_MAPPING.get(stage_id)

    if mapping is not None:
        result = dict(mapping)

        if stage_id == "REMOVABLE_MEDIA":
            result["note"] = (
                "USB 연결은 반출 가능성을 나타내는 보조 증거이며, "
                "실제 파일 복사가 확인된 경우에만 기법 확정도가 높아집니다."
            )
        elif stage_id == "ACCOUNT_ACCESS":
            result["note"] = (
                "반복 로그인 실패 이후 성공한 인증 흐름을 근거로 한 "
                "행위 기반 후보 매핑입니다."
            )
        elif stage_id == "SENSITIVE_ACCESS":
            result["note"] = (
                "민감 파일 접근을 로컬 데이터 수집 가능 행위로 매핑합니다."
            )
        else:
            result["note"] = "관측된 이벤트 증거를 기반으로 매핑했습니다."

        return result

    if stage_id == "SUSPICIOUS_EXECUTION":
        process_name = (
            getattr(event, "process_name", None)
            or ""
        ).lower()

        if process_name in {"powershell.exe", "pwsh.exe"}:
            return {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "Execution",
                "confidence": "HIGH",
                "note": "PowerShell 프로세스 실행이 직접 관측되었습니다."
            }

        if process_name == "cmd.exe":
            return {
                "technique_id": "T1059.003",
                "technique_name": "Windows Command Shell",
                "tactic": "Execution",
                "confidence": "HIGH",
                "note": "Windows Command Shell 실행이 직접 관측되었습니다."
            }

        return {
            "technique_id": None,
            "technique_name": "ATT&CK 미확정",
            "tactic": "Evidence Only",
            "confidence": "NONE",
            "note": (
                "프로세스 실행만으로 네트워크 전송 또는 C2/Exfiltration "
                "기법을 단정하지 않습니다."
            )
        }

    return {
        "technique_id": None,
        "technique_name": "ATT&CK 미확정",
        "tactic": "Evidence Only",
        "confidence": "NONE",
        "note": "현재 수집 증거만으로 ATT&CK Technique을 확정하지 않습니다."
    }


def _stage(
    stage_id,
    name,
    description,
    event,
    score
):
    mitre = _get_mitre_mapping(
        stage_id,
        event
    )

    return {
        "stage_id": stage_id,
        "name": name,
        "description": description,
        "event_id": event.id,
        "event_type": event.event_type,
        "timestamp": _event_time(
            event
        ).isoformat(),
        "score": score,
        "mitre_technique_id": mitre.get("technique_id"),
        "mitre_technique_name": mitre.get("technique_name"),
        "mitre_tactic": mitre.get("tactic"),
        "mitre_confidence": mitre.get("confidence"),
        "mitre_note": mitre.get("note")
    }


def analyze_incident_pattern(events):
    events = sorted(
        events,
        key=lambda item: (
            _event_time(item),
            item.id
        )
    )

    stages = []
    storyline = []
    score = 0

    failed_events = [
        event
        for event in events
        if event.event_type == "login_failed"
    ]

    credential_event = None

    if len(failed_events) >= 3:
        credential_event = failed_events[2]

        stages.append(
            _stage(
                "CREDENTIAL_FAILURE",
                "반복 로그인 실패",
                (
                    f"상관분석 시간창에서 로그인 실패 "
                    f"{len(failed_events)}회 확인"
                ),
                credential_event,
                20
            )
        )

        score += 20

    login_success_event = None

    if credential_event is not None:
        for event in events:
            if (
                event.event_type
                == "login_success"
                and _event_time(event)
                >= _event_time(
                    credential_event
                )
            ):
                login_success_event = event
                break

    if login_success_event is not None:
        stages.append(
            _stage(
                "ACCOUNT_ACCESS",
                "로그인 성공",
                "반복 로그인 실패 이후 로그인 성공",
                login_success_event,
                20
            )
        )

        score += 20

    sensitive_file_event = None

    for event in events:
        if (
            event.event_type == "file_access"
            and event.file_grade
            in {
                "내부",
                "대외비"
            }
        ):
            if (
                login_success_event is None
                or _event_time(event)
                >= _event_time(
                    login_success_event
                )
            ):
                sensitive_file_event = event
                break

    if sensitive_file_event is not None:
        file_score = (
            25
            if sensitive_file_event.file_grade
            == "대외비"
            else 15
        )

        stages.append(
            _stage(
                "SENSITIVE_ACCESS",
                "중요 문서 접근",
                (
                    f"{sensitive_file_event.file_grade} "
                    f"문서 접근: "
                    f"{sensitive_file_event.file_name or '-'}"
                ),
                sensitive_file_event,
                file_score
            )
        )

        score += file_score

    bulk_file_event = None

    for event in events:
        if (
            event.event_type == "file_access"
            and (
                event.file_access_count
                or 0
            ) >= 20
        ):
            bulk_file_event = event
            break

    if bulk_file_event is not None:
        if (
            sensitive_file_event is None
            or bulk_file_event.id
            != sensitive_file_event.id
        ):
            stages.append(
                _stage(
                    "COLLECTION",
                    "대량 파일 접근",
                    (
                        "단시간 파일 접근량 "
                        f"{bulk_file_event.file_access_count}회"
                    ),
                    bulk_file_event,
                    20
                )
            )

        score += 20

    usb_event = None

    for event in events:
        if (
            event.event_type
            == "usb_connected"
            or event.usb_connected == 1
        ):
            if (
                sensitive_file_event is None
                or _event_time(event)
                >= _event_time(
                    sensitive_file_event
                )
            ):
                usb_event = event
                break

    if usb_event is not None:
        stages.append(
            _stage(
                "REMOVABLE_MEDIA",
                "USB 저장장치 연결",
                "중요 정보 반출 가능 이동식 저장장치 연결",
                usb_event,
                20
            )
        )

        score += 20

    suspicious_process_event = None

    for event in events:
        process_name = (
            event.process_name
            or ""
        ).lower()

        if (
            event.event_type
            == "process_execution"
            and process_name
            in SUSPICIOUS_PROCESSES
        ):
            if (
                sensitive_file_event is None
                or _event_time(event)
                >= _event_time(
                    sensitive_file_event
                )
            ):
                suspicious_process_event = event
                break

    if suspicious_process_event is not None:
        stages.append(
            _stage(
                "SUSPICIOUS_EXECUTION",
                "의심 프로세스 실행",
                (
                    "정보 수집·전송에 악용될 수 있는 "
                    f"프로세스 실행: "
                    f"{suspicious_process_event.process_name}"
                ),
                suspicious_process_event,
                20
            )
        )

        score += 20

    stages = sorted(
        stages,
        key=lambda item: (
            item["timestamp"],
            item["event_id"]
        )
    )

    for index, stage in enumerate(
        stages,
        start=1
    ):
        storyline.append(
            {
                "order": index,
                **stage
            }
        )

    unique_stage_ids = {
        item["stage_id"]
        for item in stages
    }

    incident_type = (
        "SUSPICIOUS_ACTIVITY_CHAIN"
    )

    title = (
        "복합 위험 행동 상관분석"
    )

    if {
        "CREDENTIAL_FAILURE",
        "ACCOUNT_ACCESS",
        "SENSITIVE_ACCESS"
    }.issubset(
        unique_stage_ids
    ):
        incident_type = (
            "ACCOUNT_COMPROMISE"
        )

        title = (
            "계정 탈취 후 중요정보 접근 의심"
        )

    if (
        "SENSITIVE_ACCESS"
        in unique_stage_ids
        and (
            "REMOVABLE_MEDIA"
            in unique_stage_ids
            or "SUSPICIOUS_EXECUTION"
            in unique_stage_ids
        )
    ):
        incident_type = (
            "DATA_EXFILTRATION"
        )

        title = (
            "중요정보 유출 의심"
        )

    if {
        "CREDENTIAL_FAILURE",
        "ACCOUNT_ACCESS",
        "SENSITIVE_ACCESS"
    }.issubset(
        unique_stage_ids
    ) and (
        "REMOVABLE_MEDIA"
        in unique_stage_ids
        or "SUSPICIOUS_EXECUTION"
        in unique_stage_ids
    ):
        incident_type = (
            "ACCOUNT_COMPROMISE_DATA_EXFILTRATION"
        )

        title = (
            "계정 탈취 후 정보 유출 의심"
        )

    score = min(
        float(score),
        100.0
    )

    # 단일 증거만으로 Incident를 만들지 않는다.
    # 서로 다른 2개 이상의 의미 있는 공격 단계가 연결되어야 한다.
    create_incident = (
        len(unique_stage_ids) >= 2
        and score >= 35
    )

    return {
        "create_incident": create_incident,
        "incident_type": incident_type,
        "title": title,
        "correlation_score": score,
        "severity": _severity(
            score
        ),
        "stages": stages,
        "storyline": storyline
    }


def correlate_security_incident(
    db: Session,
    user: str,
    reference_time=None
):
    reference_time = (
        reference_time
        or datetime.now()
    )

    since = (
        reference_time
        - timedelta(
            minutes=INCIDENT_WINDOW_MINUTES
        )
    )

    events = (
        db.query(
            SecurityEvent
        )
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp >= since,
            SecurityEvent.timestamp
            <= reference_time
        )
        .order_by(
            SecurityEvent.timestamp.asc(),
            SecurityEvent.id.asc()
        )
        .all()
    )

    result = analyze_incident_pattern(
        events
    )

    if not result[
        "create_incident"
    ]:
        return {
            "incident_created": False,
            "incident_updated": False,
            "incident": None,
            "correlation": result
        }

    relevant_event_ids = sorted(
        {
            stage["event_id"]
            for stage in result[
                "stages"
            ]
        }
    )

    relevant_events = [
        event
        for event in events
        if event.id
        in relevant_event_ids
    ]

    if not relevant_events:
        return {
            "incident_created": False,
            "incident_updated": False,
            "incident": None,
            "correlation": result
        }

    start_time = min(
        _event_time(event)
        for event in relevant_events
    )

    end_time = max(
        _event_time(event)
        for event in relevant_events
    )

    # 같은 사용자의 OPEN/INVESTIGATING 사고가 같은 시간창에서
    # 이어지면 새 사고를 만들지 않고 기존 Incident를 갱신한다.
    existing = (
        db.query(
            SecurityIncident
        )
        .filter(
            SecurityIncident.user == user,
            SecurityIncident.status.in_(
                [
                    "OPEN",
                    "INVESTIGATING"
                ]
            ),
            SecurityIncident.end_time
            >= since
        )
        .order_by(
            SecurityIncident.id.desc()
        )
        .first()
    )

    summary = (
        f"{user} 사용자의 최근 "
        f"{INCIDENT_WINDOW_MINUTES}분 행동에서 "
        f"{len(result['stages'])}개 공격 단계를 "
        f"상관분석하여 {result['title']} 패턴을 탐지"
    )

    created = False

    if existing is None:
        incident = SecurityIncident(
            user=user,
            incident_type=result[
                "incident_type"
            ],
            title=result[
                "title"
            ],
            severity=result[
                "severity"
            ],
            correlation_score=result[
                "correlation_score"
            ],
            status="OPEN",
            start_time=start_time,
            end_time=end_time,
            event_count=len(
                relevant_event_ids
            ),
            event_ids_json=json.dumps(
                relevant_event_ids,
                ensure_ascii=False
            ),
            stages_json=json.dumps(
                result["stages"],
                ensure_ascii=False
            ),
            storyline_json=json.dumps(
                result["storyline"],
                ensure_ascii=False
            ),
            summary=summary,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )

        db.add(
            incident
        )

        created = True

    else:
        incident = existing

        old_ids = set()

        try:
            old_ids = set(
                json.loads(
                    incident.event_ids_json
                    or "[]"
                )
            )
        except (
            TypeError,
            ValueError
        ):
            old_ids = set()

        merged_ids = sorted(
            old_ids
            | set(
                relevant_event_ids
            )
        )

        incident.incident_type = result[
            "incident_type"
        ]

        incident.title = result[
            "title"
        ]

        incident.severity = result[
            "severity"
        ]

        incident.correlation_score = result[
            "correlation_score"
        ]

        incident.start_time = min(
            incident.start_time,
            start_time
        )

        incident.end_time = max(
            incident.end_time,
            end_time
        )

        incident.event_count = len(
            merged_ids
        )

        incident.event_ids_json = (
            json.dumps(
                merged_ids,
                ensure_ascii=False
            )
        )

        incident.stages_json = (
            json.dumps(
                result["stages"],
                ensure_ascii=False
            )
        )

        incident.storyline_json = (
            json.dumps(
                result["storyline"],
                ensure_ascii=False
            )
        )

        incident.summary = summary
        incident.updated_at = datetime.now()

    db.commit()
    db.refresh(
        incident
    )

    return {
        "incident_created": created,
        "incident_updated": not created,
        "incident": serialize_incident(
            incident
        ),
        "correlation": result
    }


def serialize_incident(incident):
    def parse_json(value):
        try:
            return json.loads(
                value
                or "[]"
            )
        except (
            TypeError,
            ValueError
        ):
            return []

    return {
        "id": incident.id,
        "user": incident.user,
        "incident_type": (
            incident.incident_type
        ),
        "title": incident.title,
        "severity": incident.severity,
        "correlation_score": (
            incident.correlation_score
        ),
        "status": incident.status,
        "start_time": (
            incident.start_time.isoformat()
            if incident.start_time
            else None
        ),
        "end_time": (
            incident.end_time.isoformat()
            if incident.end_time
            else None
        ),
        "event_count": incident.event_count,
        "event_ids": parse_json(
            incident.event_ids_json
        ),
        "stages": parse_json(
            incident.stages_json
        ),
        "storyline": parse_json(
            incident.storyline_json
        ),
        "summary": incident.summary,
        "created_at": (
            incident.created_at.isoformat()
            if incident.created_at
            else None
        ),
        "updated_at": (
            incident.updated_at.isoformat()
            if incident.updated_at
            else None
        )
    }


def get_incidents(
    db: Session,
    user=None,
    status=None
):
    query = db.query(
        SecurityIncident
    )

    if user:
        query = query.filter(
            SecurityIncident.user == user
        )

    if status:
        query = query.filter(
            SecurityIncident.status == status
        )

    incidents = (
        query
        .order_by(
            SecurityIncident.id.desc()
        )
        .all()
    )

    return [
        serialize_incident(
            incident
        )
        for incident in incidents
    ]


def get_incident(
    db: Session,
    incident_id: int
):
    incident = (
        db.query(
            SecurityIncident
        )
        .filter(
            SecurityIncident.id
            == incident_id
        )
        .first()
    )

    if incident is None:
        return None

    return serialize_incident(
        incident
    )


def update_incident_status(
    db: Session,
    incident_id: int,
    status: str
):
    allowed = {
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "CLOSED"
    }

    status = status.upper()

    if status not in allowed:
        return None, (
            "지원 상태: OPEN, INVESTIGATING, "
            "CONTAINED, CLOSED"
        )

    incident = (
        db.query(
            SecurityIncident
        )
        .filter(
            SecurityIncident.id
            == incident_id
        )
        .first()
    )

    if incident is None:
        return None, (
            "사고를 찾을 수 없습니다."
        )

    incident.status = status
    incident.updated_at = datetime.now()

    db.commit()
    db.refresh(
        incident
    )

    return (
        serialize_incident(
            incident
        ),
        None
    )
