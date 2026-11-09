from datetime import datetime, timedelta
from sqlalchemy import text

OBSERVE_MIN_COUNT = 3
OBSERVE_MIN_HOURS = 1

STRONG_RISK_KEYWORDS = (
    "대외비",
    "민감",
    "USB",
    "반복 로그인 실패",
    "로그인 실패",
    "공격 시퀀스",
    "Sequence",
    "의심 명령",
    "외부 다운로드",
    "대량 파일",
)


def _ensure_change_column(db, column_name, definition):
    """기존 SQLite DB에도 수동 판정 컬럼을 안전하게 추가한다."""
    columns = db.execute(
        text("PRAGMA table_info(behavior_change_observations)")
    ).mappings().all()

    existing_columns = {
        str(column["name"])
        for column in columns
    }

    if column_name not in existing_columns:
        db.execute(
            text(
                f"ALTER TABLE behavior_change_observations "
                f"ADD COLUMN {column_name} {definition}"
            )
        )
        db.commit()


def ensure_change_table(db):
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
            manual_override INTEGER NOT NULL DEFAULT 0,
            manual_note TEXT,
            decided_at DATETIME,
            UNIQUE(user, change_type, change_value)
        )
    """))
    db.commit()

    # 이미 생성된 DB를 사용하는 경우에도 자동 마이그레이션한다.
    _ensure_change_column(
        db,
        "manual_override",
        "INTEGER NOT NULL DEFAULT 0"
    )
    _ensure_change_column(
        db,
        "manual_note",
        "TEXT"
    )
    _ensure_change_column(
        db,
        "decided_at",
        "DATETIME"
    )


def _extract_candidates(event):
    candidates = []

    source_ip = getattr(event, "source_ip", None)
    if source_ip:
        candidates.append(("IP", str(source_ip).strip()))

    process_name = getattr(event, "process_name", None)
    if process_name:
        candidates.append(("PROCESS", str(process_name).strip().lower()))

    device_id = getattr(event, "device_id", None)
    device_name = getattr(event, "device_name", None)
    host = getattr(event, "host", None)
    workstation_name = getattr(event, "workstation_name", None)

    if device_id:
        candidates.append(("DEVICE", str(device_id).strip()))
    elif device_name:
        candidates.append(("DEVICE", str(device_name).strip()))
    elif host and workstation_name:
        host_value = str(host).strip()
        workstation_value = str(workstation_name).strip()

        # HOST와 WORKSTATION이 실제로 서로 다른 경우에만
        # 별도 HOST 행동 변화로 검증한다.
        # workstation_name이 없으면 확장 엔진이 host를 WORKSTATION으로
        # 사용하므로 여기서는 HOST를 추가하지 않는다.
        if host_value.lower() != workstation_value.lower():
            candidates.append(("HOST", host_value))

    result = []
    seen = set()

    for item in candidates:
        if not item[1] or item in seen:
            continue

        seen.add(item)
        result.append(item)

    return result

def _has_strong_risk_context(event):
    risk_score = float(getattr(event, "risk_score", 0) or 0)
    risk_level = str(getattr(event, "risk_level", "") or "")
    reasons = str(getattr(event, "reasons", "") or "")

    if risk_score >= 60 or risk_level in ("HIGH", "CRITICAL"):
        return True

    return any(keyword in reasons for keyword in STRONG_RISK_KEYWORDS)


def _already_known_in_low_history(db, event, change_type, change_value):
    from server.models import SecurityEvent

    q = db.query(SecurityEvent).filter(
        SecurityEvent.user == event.user,
        SecurityEvent.id != event.id,
        SecurityEvent.risk_level == "LOW",
        SecurityEvent.timestamp < event.timestamp,
    )

    if change_type == "IP":
        q = q.filter(SecurityEvent.source_ip == change_value)
        return q.first() is not None

    if change_type == "PROCESS":
        rows = q.filter(SecurityEvent.process_name.isnot(None)).all()
        target = change_value.lower()
        return any(
            str(row.process_name).strip().lower() == target
            for row in rows
        )

    if change_type == "DEVICE":
        rows = q.all()
        for row in rows:
            rid = getattr(row, "device_id", None)
            rname = getattr(row, "device_name", None)
            if rid and str(rid).strip() == change_value:
                return True
            if (not rid) and rname and str(rname).strip() == change_value:
                return True
        return False

    if change_type == "HOST":
        if hasattr(SecurityEvent, "host"):
            q = q.filter(SecurityEvent.host == change_value)
            return q.first() is not None
        return False

    return False


def evaluate_behavior_change(db, event):
    ensure_change_table(db)

    results = []
    risky = _has_strong_risk_context(event)

    for change_type, change_value in _extract_candidates(event):
        row = db.execute(
            text("""
                SELECT id, status, first_seen, last_seen, seen_count,
                       max_risk_score, risky_context_count, decision_reason,
                       manual_override, manual_note, decided_at
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

        if (
            row is None
            and not risky
            and _already_known_in_low_history(
                db, event, change_type, change_value
            )
        ):
            continue

        now = event.timestamp or datetime.now()
        risk_score = float(getattr(event, "risk_score", 0) or 0)

        if row is None:
            status = "REJECTED" if risky else "OBSERVING"
            reason = (
                "강한 위험 신호와 함께 나타나 정상 기준선 학습에서 제외"
                if risky
                else "새 행동 감지: 정상 여부 관찰 중 (1/3회)"
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
                        :first_seen, :last_seen, 1,
                        :max_risk_score, :risky_context_count, :reason
                    )
                """),
                {
                    "user": event.user,
                    "change_type": change_type,
                    "change_value": change_value,
                    "status": status,
                    "first_seen": now,
                    "last_seen": now,
                    "max_risk_score": risk_score,
                    "risky_context_count": 1 if risky else 0,
                    "reason": reason,
                },
            )
            db.commit()

        else:
            status = str(row["status"])

            if status == "ACCEPTED":
                manual_override = bool(row["manual_override"] or 0)

                # 관리자가 명시적으로 정상 승인한 행동은 Behavior Change
                # 상태만 ACCEPTED로 유지한다. Rule / Sequence / Incident
                # 위험 탐지는 이 상태와 별개이므로 공격 탐지가 무력화되지 않는다.
                if manual_override:
                    results.append({
                        "type": change_type,
                        "value": change_value,
                        "status": status,
                        "reason": (
                            row["decision_reason"]
                            or "SOC 관리자 수동 승인 정상 행동"
                        ),
                        "manual_override": True,
                    })
                    continue

                if risky:
                    new_status = "REJECTED"
                    reason = (
                        "기존 자동 정상 승인 행동에서 강한 위험 맥락이 새로 확인되어 "
                        "정상 기준선 학습에서 제외"
                    )
                    db.execute(
                        text("""
                            UPDATE behavior_change_observations
                               SET status=:status,
                                   last_seen=:last_seen,
                                   seen_count=seen_count + 1,
                                   max_risk_score=:max_risk_score,
                                   risky_context_count=risky_context_count + 1,
                                   decision_reason=:reason
                             WHERE id=:id
                        """),
                        {
                            "status": new_status,
                            "last_seen": now,
                            "max_risk_score": max(
                                float(row["max_risk_score"] or 0),
                                risk_score,
                            ),
                            "reason": reason,
                            "id": row["id"],
                        },
                    )
                    db.commit()
                    status = new_status
                else:
                    results.append({
                        "type": change_type,
                        "value": change_value,
                        "status": status,
                        "reason": "검증 완료된 정상 변화",
                        "manual_override": False,
                    })
                    continue

            elif status == "REJECTED":
                results.append({
                    "type": change_type,
                    "value": change_value,
                    "status": status,
                    "reason": row["decision_reason"]
                    or "위험 변화로 판정되어 정상 학습에서 제외",
                    "manual_override": bool(row["manual_override"] or 0),
                })
                continue

            else:
                seen_count = int(row["seen_count"] or 0) + 1
                risky_count = int(row["risky_context_count"] or 0)
                if risky:
                    risky_count += 1

                max_risk = max(
                    float(row["max_risk_score"] or 0),
                    risk_score
                )

                first_seen = row["first_seen"]
                if isinstance(first_seen, str):
                    first_seen = datetime.fromisoformat(first_seen)

                elapsed = now - first_seen

                if risky:
                    new_status = "REJECTED"
                    reason = (
                        "관찰 중 강한 위험 맥락 확인: "
                        "정상 기준선 학습에서 제외"
                    )
                elif (
                    seen_count >= OBSERVE_MIN_COUNT
                    and elapsed >= timedelta(hours=OBSERVE_MIN_HOURS)
                ):
                    new_status = "ACCEPTED"
                    reason = (
                        "3회 이상·1시간 이상 반복 관찰했고 "
                        "강한 위험 신호가 없어 정상 변화로 승인"
                    )
                else:
                    new_status = "OBSERVING"
                    reason = (
                        f"정상 여부 관찰 중 "
                        f"({seen_count}/{OBSERVE_MIN_COUNT}회, "
                        f"{elapsed.total_seconds() / 3600:.1f}시간)"
                    )

                db.execute(
                    text("""
                        UPDATE behavior_change_observations
                           SET status=:status,
                               last_seen=:last_seen,
                               seen_count=:seen_count,
                               max_risk_score=:max_risk_score,
                               risky_context_count=:risky_context_count,
                               decision_reason=:reason
                         WHERE id=:id
                    """),
                    {
                        "status": new_status,
                        "last_seen": now,
                        "seen_count": seen_count,
                        "max_risk_score": max_risk,
                        "risky_context_count": risky_count,
                        "reason": reason,
                        "id": row["id"],
                    },
                )
                db.commit()
                status = new_status

        results.append({
            "type": change_type,
            "value": change_value,
            "status": status,
            "reason": reason,
        })

    return results


def is_event_allowed_for_baseline(db, event):
    ensure_change_table(db)

    for change_type, change_value in _extract_candidates(event):
        row = db.execute(
            text("""
                SELECT status
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

        if row and row["status"] in ("OBSERVING", "REJECTED"):
            return False

    return True


def get_behavior_changes(db, user=None, status=None):
    ensure_change_table(db)

    sql = """
        SELECT id, user, change_type, change_value, status,
               first_seen, last_seen, seen_count,
               max_risk_score, risky_context_count, decision_reason,
               manual_override, manual_note, decided_at
        FROM behavior_change_observations
        WHERE 1=1
    """
    params = {}

    if user:
        sql += " AND user=:user"
        params["user"] = user

    if status:
        normalized_status = str(status).strip().upper()
        if normalized_status in ("OBSERVING", "ACCEPTED", "REJECTED"):
            sql += " AND status=:status"
            params["status"] = normalized_status

    sql += " ORDER BY last_seen DESC"

    rows = db.execute(text(sql), params).mappings().all()
    return [dict(row) for row in rows]

def update_behavior_change_decision(
    db,
    observation_id,
    action,
    note=None
):
    """
    SOC 관리자가 행동 변화를 수동 판정한다.

    approve:
        정상 행동으로 승인(화이트리스트).
        Behavior Change/Baseline 관점에서 ACCEPTED로 유지한다.

    reject:
        위험 행동으로 유지한다.

    reset:
        수동 판정을 해제하고 OBSERVING으로 되돌린다.

    주의:
        이 판정은 Behavior Change/Baseline 학습 제어용이다.
        Rule, ML, Sequence, Incident 위험 탐지를 비활성화하지 않는다.
    """
    ensure_change_table(db)

    row = db.execute(
        text("""
            SELECT
                id,
                user,
                change_type,
                change_value,
                status,
                manual_override
            FROM behavior_change_observations
            WHERE id=:id
        """),
        {
            "id": observation_id
        }
    ).mappings().first()

    if row is None:
        return None, "행동 변화 항목을 찾을 수 없습니다."

    normalized_action = str(action or "").strip().lower()
    normalized_note = (
        str(note).strip()
        if note is not None and str(note).strip()
        else None
    )
    now = datetime.now()

    if normalized_action in (
        "approve",
        "accept",
        "whitelist"
    ):
        new_status = "ACCEPTED"
        reason = "SOC 관리자 수동 승인: 정상 행동으로 화이트리스트 등록"
        manual_override = 1

    elif normalized_action in (
        "reject",
        "deny",
        "block"
    ):
        new_status = "REJECTED"
        reason = "SOC 관리자 수동 판정: 위험 행동으로 유지"
        manual_override = 1

    elif normalized_action in (
        "reset",
        "observe",
        "review"
    ):
        new_status = "OBSERVING"
        reason = "SOC 관리자 수동 판정 해제: 재관찰 상태로 변경"
        manual_override = 0

    else:
        return (
            None,
            "action은 approve, reject, reset 중 하나여야 합니다."
        )

    db.execute(
        text("""
            UPDATE behavior_change_observations
               SET status=:status,
                   decision_reason=:reason,
                   manual_override=:manual_override,
                   manual_note=:manual_note,
                   decided_at=:decided_at
             WHERE id=:id
        """),
        {
            "status": new_status,
            "reason": reason,
            "manual_override": manual_override,
            "manual_note": normalized_note,
            "decided_at": now,
            "id": observation_id,
        }
    )
    db.commit()

    updated = db.execute(
        text("""
            SELECT
                id,
                user,
                change_type,
                change_value,
                status,
                first_seen,
                last_seen,
                seen_count,
                max_risk_score,
                risky_context_count,
                decision_reason,
                manual_override,
                manual_note,
                decided_at
            FROM behavior_change_observations
            WHERE id=:id
        """),
        {
            "id": observation_id
        }
    ).mappings().first()

    return dict(updated), None

