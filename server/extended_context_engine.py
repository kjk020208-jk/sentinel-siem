from datetime import datetime, timedelta
import ipaddress
import re
from sqlalchemy import text

CONTEXT_HISTORY_DAYS = 30
FILE_BURST_MINUTES = 5
FILE_BURST_THRESHOLD = 20
OBSERVE_MIN_COUNT = 3
OBSERVE_MIN_HOURS = 1

SUSPICIOUS_COMMAND_PATTERNS = (
    (r"(?i)(?:-|/)(?:enc|encodedcommand)\b", "PowerShell 인코딩 명령"),
    (r"(?i)\b(?:invoke-webrequest|iwr|wget|curl)\b", "외부 다운로드 명령"),
    (r"(?i)\b(?:downloadstring|downloadfile)\b", "스크립트 다운로드 명령"),
    (r"(?i)\bfrombase64string\b", "Base64 디코딩 명령"),
    (r"(?i)\b(?:certutil|bitsadmin)\b", "파일 전송/변환 도구 실행"),
    (r"(?i)\bpowershell(?:\.exe)?\b.*\b(?:-nop|-noprofile|-w\s+hidden|-windowstyle\s+hidden)\b", "은닉 PowerShell 실행"),
    (r"(?i)\b(?:rundll32|regsvr32|mshta)\b", "LOLBIN 계열 실행"),
)

STRONG_CONTEXT_KEYWORDS = (
    "대외비", "민감", "USB", "반복 로그인 실패", "로그인 실패",
    "의심 명령", "외부 다운로드", "대량 파일", "공격 시퀀스", "정보 유출",
)

def ensure_context_tables(db):
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS event_context (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER UNIQUE,
            user TEXT NOT NULL,
            timestamp DATETIME NOT NULL,
            source_ip TEXT,
            network_prefix TEXT,
            workstation_name TEXT,
            host TEXT,
            logon_type TEXT,
            command_line TEXT,
            parent_process TEXT,
            is_normal INTEGER NOT NULL DEFAULT 0
        )
    """))
    db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_event_context_user_time
        ON event_context(user, timestamp)
    """))
    db.execute(text("""
        CREATE INDEX IF NOT EXISTS ix_event_context_user_normal
        ON event_context(user, is_normal)
    """))
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS behavior_change_observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            change_type TEXT NOT NULL,
            change_value TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OBSERVING',
            first_seen DATETIME NOT NULL,
            last_seen DATETIME NOT NULL,
            seen_count INTEGER NOT NULL DEFAULT 1,
            max_risk_score REAL NOT NULL DEFAULT 0,
            risky_context_count INTEGER NOT NULL DEFAULT 0,
            decision_reason TEXT,
            UNIQUE(user, change_type, change_value)
        )
    """))
    db.commit()

def _clean(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value or value == "-":
        return None
    return value

def _network_prefix(source_ip):
    source_ip = _clean(source_ip)
    if not source_ip:
        return None
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return None
    if ip.version == 4:
        return str(ipaddress.ip_network(f"{source_ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{source_ip}/64", strict=False))

def _device_key(event):
    workstation = _clean(getattr(event, "workstation_name", None))
    if workstation:
        return workstation
    device_id = _clean(getattr(event, "device_id", None))
    if device_id:
        return device_id
    device_name = _clean(getattr(event, "device_name", None))
    if device_name:
        return device_name
    return _clean(getattr(event, "host", None))

def _history_rows(db, user, reference_time):
    ensure_context_tables(db)
    since = reference_time - timedelta(days=CONTEXT_HISTORY_DAYS)
    return db.execute(
        text("""
            SELECT source_ip, network_prefix, workstation_name, host,
                   logon_type, command_line, parent_process, timestamp
            FROM event_context
            WHERE user=:user
              AND is_normal=1
              AND timestamp < :reference_time
              AND timestamp >= :since
            ORDER BY timestamp DESC
        """),
        {"user": user, "reference_time": reference_time, "since": since},
    ).mappings().all()

def _frequent_values(rows, key, min_count=2):
    counts = {}
    for row in rows:
        value = _clean(row.get(key))
        if value:
            counts[value] = counts.get(value, 0) + 1
    return {value for value, count in counts.items() if count >= min_count}

def _suspicious_command(command_line):
    command_line = _clean(command_line)
    if not command_line:
        return []
    matches = []
    for pattern, label in SUSPICIOUS_COMMAND_PATTERNS:
        if re.search(pattern, command_line):
            matches.append(label)
    return list(dict.fromkeys(matches))

def _recent_file_access_count(db, user, reference_time):
    from server.models import SecurityEvent
    since = reference_time - timedelta(minutes=FILE_BURST_MINUTES)
    rows = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.event_type == "file_access",
            SecurityEvent.timestamp >= since,
            SecurityEvent.timestamp <= reference_time,
        )
        .all()
    )
    total = 0
    for row in rows:
        count = int(getattr(row, "file_access_count", 0) or 0)
        total += max(1, count)
    return total

def analyze_extended_context(db, event, reference_time=None):
    if reference_time is None:
        reference_time = getattr(event, "timestamp", None) or datetime.now()

    ensure_context_tables(db)

    source_ip = _clean(getattr(event, "source_ip", None))
    network_prefix = _network_prefix(source_ip)
    workstation = _clean(getattr(event, "workstation_name", None))
    host = _clean(getattr(event, "host", None))
    logon_type = _clean(getattr(event, "logon_type", None))
    command_line = _clean(getattr(event, "command_line", None))
    parent_process = _clean(getattr(event, "parent_process", None))

    rows = _history_rows(db, event.user, reference_time)
    score = 0
    reasons = []

    known_prefixes = _frequent_values(rows, "network_prefix", 2)
    if network_prefix and known_prefixes and network_prefix not in known_prefixes:
        score += 15
        reasons.append(f"평소 사용 대역과 다른 네트워크 접속: {network_prefix}")

    device_value = workstation or _device_key(event)
    known_workstations = _frequent_values(rows, "workstation_name", 2)
    known_hosts = _frequent_values(rows, "host", 2)
    known_devices = known_workstations | known_hosts

    if device_value and known_devices and device_value not in known_devices:
        score += 20
        reasons.append(f"평소 사용하지 않던 PC·장치에서의 접속: {device_value}")

    known_logon_types = _frequent_values(rows, "logon_type", 2)
    if logon_type and known_logon_types and logon_type not in known_logon_types:
        score += 10
        reasons.append(f"평소와 다른 로그인 접속 환경(LogonType {logon_type})")

    command_matches = _suspicious_command(command_line)
    if command_matches:
        score += min(30, 15 + 5 * len(command_matches))
        reasons.append("의심 명령 실행: " + ", ".join(command_matches))

    if getattr(event, "event_type", None) == "file_access":
        recent_count = _recent_file_access_count(db, event.user, reference_time)
        current_count = int(getattr(event, "file_access_count", 0) or 0)
        if recent_count == 0:
            recent_count = max(1, current_count)
        if recent_count >= FILE_BURST_THRESHOLD:
            score += 20
            reasons.append(
                f"{FILE_BURST_MINUTES}분 이내 대량 파일 접근 {recent_count}건 감지"
            )

    context = {
        "source_ip": source_ip,
        "network_prefix": network_prefix,
        "workstation_name": workstation,
        "host": host,
        "logon_type": logon_type,
        "command_line": command_line,
        "parent_process": parent_process,
    }
    return min(score, 60), reasons, context

def _strong_risk(risk_score, risk_level, reasons):
    if float(risk_score or 0) >= 60:
        return True
    if str(risk_level or "") in ("HIGH", "CRITICAL"):
        return True
    text_value = " ".join(str(x) for x in (reasons or []))
    return any(keyword in text_value for keyword in STRONG_CONTEXT_KEYWORDS)

def _candidate_risky(change_type, risk_score, risk_level, reasons):
    """
    행동 변화 후보 자체와 관련된 위험 신호만 해당 후보의
    REJECTED 판정에 사용한다.

    예:
    USB 연결 위험 때문에 정상 WORKSTATION까지 REJECTED 되는
    cross-contamination을 방지한다.
    """
    reason_text = " ".join(str(x) for x in (reasons or []))

    if change_type == "NETWORK":
        return "평소 사용 대역과 다른 네트워크" in reason_text

    if change_type == "WORKSTATION":
        return "평소 사용하지 않던 PC·장치" in reason_text

    if change_type == "LOGON_TYPE":
        return "평소와 다른 로그인 접속 환경" in reason_text

    return _strong_risk(
        risk_score,
        risk_level,
        reasons
    )


def _extended_candidates(event):
    result = []
    prefix = _network_prefix(getattr(event, "source_ip", None))
    if prefix:
        result.append(("NETWORK", prefix))
    device = _device_key(event)
    if device:
        result.append(("WORKSTATION", device))
    logon_type = _clean(getattr(event, "logon_type", None))
    if logon_type:
        result.append(("LOGON_TYPE", logon_type))
    return result

def evaluate_extended_behavior_changes(
    db, event, risk_score, risk_level, reasons, reference_time=None
):
    ensure_context_tables(db)
    if reference_time is None:
        reference_time = getattr(event, "timestamp", None) or datetime.now()

    output = []

    for change_type, change_value in _extended_candidates(event):
        risky = _candidate_risky(
            change_type,
            risk_score,
            risk_level,
            reasons
        )
        row = db.execute(
            text("""
                SELECT id, status, first_seen, last_seen, seen_count,
                       max_risk_score, risky_context_count, decision_reason
                FROM behavior_change_observations
                WHERE user=:user
                  AND change_type=:change_type
                  AND change_value=:change_value
            """),
            {
                "user": event.user,
                "change_type": change_type,
                "change_value": change_value,
            },
        ).mappings().first()

        if row is None:
            status = "REJECTED" if risky else "OBSERVING"
            reason = (
                "강한 위험 신호와 함께 처음 나타나 정상 기준선 학습에서 제외"
                if risky else
                "새 행동 감지: 정상 여부 관찰 중 (1/3회)"
            )
            db.execute(
                text("""
                    INSERT INTO behavior_change_observations
                    (
                        user, change_type, change_value, status,
                        first_seen, last_seen, seen_count,
                        max_risk_score, risky_context_count, decision_reason
                    )
                    VALUES
                    (
                        :user, :change_type, :change_value, :status,
                        :now, :now, 1,
                        :risk_score, :risky_count, :reason
                    )
                """),
                {
                    "user": event.user,
                    "change_type": change_type,
                    "change_value": change_value,
                    "status": status,
                    "now": reference_time,
                    "risk_score": float(risk_score or 0),
                    "risky_count": 1 if risky else 0,
                    "reason": reason,
                },
            )
            db.commit()
            output.append({
                "type": change_type,
                "value": change_value,
                "status": status,
                "reason": reason,
            })
            continue

        status = str(row["status"])
        if status in ("ACCEPTED", "REJECTED"):
            output.append({
                "type": change_type,
                "value": change_value,
                "status": status,
                "reason": row["decision_reason"] or (
                    "검증 완료된 정상 변화"
                    if status == "ACCEPTED"
                    else "위험 변화로 판정되어 정상 학습에서 제외"
                ),
            })
            continue

        first_seen = row["first_seen"]
        if isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen)

        seen_count = int(row["seen_count"] or 0) + 1
        elapsed_hours = (reference_time - first_seen).total_seconds() / 3600.0

        if risky:
            status = "REJECTED"
            reason = "관찰 중 강한 위험 맥락 확인: 정상 기준선 학습에서 제외"
        elif seen_count >= OBSERVE_MIN_COUNT and elapsed_hours >= OBSERVE_MIN_HOURS:
            status = "ACCEPTED"
            reason = (
                f"{OBSERVE_MIN_COUNT}회 이상·{OBSERVE_MIN_HOURS}시간 이상 반복 관찰했고 "
                "강한 위험 신호가 없어 정상 변화로 승인"
            )
        else:
            status = "OBSERVING"
            reason = (
                f"정상 여부 관찰 중 ({seen_count}/{OBSERVE_MIN_COUNT}회, "
                f"{elapsed_hours:.1f}시간)"
            )

        db.execute(
            text("""
                UPDATE behavior_change_observations
                SET status=:status,
                    last_seen=:last_seen,
                    seen_count=:seen_count,
                    max_risk_score=:max_risk_score,
                    risky_context_count=risky_context_count + :risky_inc,
                    decision_reason=:reason
                WHERE id=:id
            """),
            {
                "status": status,
                "last_seen": reference_time,
                "seen_count": seen_count,
                "max_risk_score": max(
                    float(row["max_risk_score"] or 0),
                    float(risk_score or 0),
                ),
                "risky_inc": 1 if risky else 0,
                "reason": reason,
                "id": row["id"],
            },
        )
        db.commit()
        output.append({
            "type": change_type,
            "value": change_value,
            "status": status,
            "reason": reason,
        })

    return output

def persist_event_context(db, db_event, event, change_results=None):
    ensure_context_tables(db)
    change_results = change_results or []
    blocked = any(
        item.get("status") in ("OBSERVING", "REJECTED")
        for item in change_results
    )
    risk_level = str(getattr(db_event, "risk_level", "") or "")
    is_normal = 1 if (risk_level == "LOW" and not blocked) else 0

    context = {
        "source_ip": _clean(getattr(event, "source_ip", None)),
        "network_prefix": _network_prefix(getattr(event, "source_ip", None)),
        "workstation_name": _clean(getattr(event, "workstation_name", None)),
        "host": _clean(getattr(event, "host", None)),
        "logon_type": _clean(getattr(event, "logon_type", None)),
        "command_line": _clean(getattr(event, "command_line", None)),
        "parent_process": _clean(getattr(event, "parent_process", None)),
    }

    db.execute(
        text("""
            INSERT OR REPLACE INTO event_context
            (
                event_id, user, timestamp,
                source_ip, network_prefix,
                workstation_name, host, logon_type,
                command_line, parent_process,
                is_normal
            )
            VALUES
            (
                :event_id, :user, :timestamp,
                :source_ip, :network_prefix,
                :workstation_name, :host, :logon_type,
                :command_line, :parent_process,
                :is_normal
            )
        """),
        {
            "event_id": db_event.id,
            "user": db_event.user,
            "timestamp": db_event.timestamp,
            **context,
            "is_normal": is_normal,
        },
    )
    db.commit()
