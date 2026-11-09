from datetime import datetime, timedelta
from sqlalchemy import text

OBSERVE_MIN_COUNT = 3
OBSERVE_MIN_HOURS = 1


def ensure_endpoint_tables(db):
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS endpoint_event_context (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL UNIQUE,
            user TEXT NOT NULL,
            agent_id TEXT,
            endpoint_ip TEXT,
            endpoint_network TEXT,
            host TEXT,
            observed_at DATETIME NOT NULL
        )
    """))
    db.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_endpoint_context_user_time
        ON endpoint_event_context(user, observed_at)
    """))
    db.commit()


def _ensure_behavior_table(db):
    # Compatible with the existing Human-in-the-loop behavior table.
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


def _accepted_values(db, user, change_type):
    _ensure_behavior_table(db)
    rows = db.execute(
        text("""
            SELECT change_value
              FROM behavior_change_observations
             WHERE user=:user
               AND change_type=:change_type
               AND status='ACCEPTED'
        """),
        {"user": user, "change_type": change_type},
    ).mappings().all()
    return {
        str(row["change_value"]).strip()
        for row in rows
        if row.get("change_value")
    }


def analyze_endpoint_context(db, event, reference_time=None):
    """Risk signal for endpoint/network changes.

    Important design rule:
    - A DHCP IP change inside the same approved network is not treated as a threat.
    - A previously unseen network is meaningful only after at least one network
      has been approved for the user.
    - A different Agent ID is a stronger device-context change.
    """
    ensure_endpoint_tables(db)
    _ensure_behavior_table(db)

    user = str(getattr(event, "user", "") or "").strip()
    endpoint_ip = str(getattr(event, "endpoint_ip", "") or "").strip() or None
    endpoint_network = str(getattr(event, "endpoint_network", "") or "").strip() or None
    agent_id = str(getattr(event, "agent_id", "") or "").strip() or None

    score = 0.0
    reasons = []

    if not user:
        return score, reasons, {
            "endpoint_ip": endpoint_ip,
            "endpoint_network": endpoint_network,
            "agent_id": agent_id,
        }

    accepted_networks = _accepted_values(db, user, "ENDPOINT_NETWORK")
    accepted_agents = _accepted_values(db, user, "AGENT_ID")

    # Network change: meaningful only after a known-good network exists.
    if (
        endpoint_network
        and accepted_networks
        and endpoint_network not in accepted_networks
    ):
        score += 15.0
        reasons.append(
            "평소 승인된 Endpoint Network와 다른 네트워크 감지: "
            f"{endpoint_network}"
        )

    # Agent/device change is stronger than a DHCP address change.
    if agent_id and accepted_agents and agent_id not in accepted_agents:
        score += 20.0
        reasons.append(
            "평소 승인된 Agent ID와 다른 감시 단말 감지: "
            f"{agent_id}"
        )

    # Do not score endpoint_ip itself. It is recorded for investigation only.
    score = min(score, 30.0)

    latest = db.execute(
        text("""
            SELECT agent_id, endpoint_ip, endpoint_network, host, observed_at
              FROM endpoint_event_context
             WHERE user=:user
             ORDER BY observed_at DESC, id DESC
             LIMIT 1
        """),
        {"user": user},
    ).mappings().first()

    return score, reasons, {
        "agent_id": agent_id,
        "endpoint_ip": endpoint_ip,
        "endpoint_network": endpoint_network,
        "accepted_networks": sorted(accepted_networks),
        "accepted_agents": sorted(accepted_agents),
        "previous": dict(latest) if latest else None,
    }


def persist_endpoint_context(db, event_id, event, reference_time=None):
    ensure_endpoint_tables(db)

    now = reference_time or getattr(event, "timestamp", None) or datetime.now()
    user = str(getattr(event, "user", "") or "").strip()
    if not user:
        return

    db.execute(
        text("""
            INSERT OR REPLACE INTO endpoint_event_context
            (event_id, user, agent_id, endpoint_ip, endpoint_network, host, observed_at)
            VALUES
            (:event_id, :user, :agent_id, :endpoint_ip, :endpoint_network, :host, :observed_at)
        """),
        {
            "event_id": event_id,
            "user": user,
            "agent_id": getattr(event, "agent_id", None),
            "endpoint_ip": getattr(event, "endpoint_ip", None),
            "endpoint_network": getattr(event, "endpoint_network", None),
            "host": getattr(event, "host", None),
            "observed_at": now,
        },
    )
    db.commit()


def _observe_one(db, user, change_type, change_value, risk_score, now):
    if not change_value:
        return None

    _ensure_behavior_table(db)

    row = db.execute(
        text("""
            SELECT id, status, first_seen, last_seen, seen_count,
                   max_risk_score, risky_context_count, decision_reason,
                   manual_override
              FROM behavior_change_observations
             WHERE user=:user
               AND change_type=:change_type
               AND change_value=:change_value
        """),
        {
            "user": user,
            "change_type": change_type,
            "change_value": change_value,
        },
    ).mappings().first()

    risky = float(risk_score or 0) >= 60

    if row is None:
        reason = "새 Endpoint 행동 감지: 정상 여부 관찰 중 (1/3회)"
        db.execute(
            text("""
                INSERT INTO behavior_change_observations
                (user, change_type, change_value, status,
                 first_seen, last_seen, seen_count,
                 max_risk_score, risky_context_count, decision_reason)
                VALUES
                (:user, :change_type, :change_value, 'OBSERVING',
                 :now, :now, 1, :risk_score, :risky_count, :reason)
            """),
            {
                "user": user,
                "change_type": change_type,
                "change_value": change_value,
                "now": now,
                "risk_score": float(risk_score or 0),
                "risky_count": 1 if risky else 0,
                "reason": reason,
            },
        )
        db.commit()
        return {
            "type": change_type,
            "value": change_value,
            "status": "OBSERVING",
            "reason": reason,
        }

    status = str(row["status"] or "OBSERVING")
    # Manual SOC decisions are sticky.
    if status in ("ACCEPTED", "REJECTED") or int(row.get("manual_override") or 0) == 1:
        db.execute(
            text("""
                UPDATE behavior_change_observations
                   SET last_seen=:now,
                       seen_count=seen_count + 1,
                       max_risk_score=:max_risk_score,
                       risky_context_count=risky_context_count + :risky_inc
                 WHERE id=:id
            """),
            {
                "now": now,
                "max_risk_score": max(
                    float(row["max_risk_score"] or 0),
                    float(risk_score or 0),
                ),
                "risky_inc": 1 if risky else 0,
                "id": row["id"],
            },
        )
        db.commit()
        return {
            "type": change_type,
            "value": change_value,
            "status": status,
            "reason": row.get("decision_reason") or "SOC 관리자 판정 유지",
        }

    seen_count = int(row["seen_count"] or 0) + 1
    first_seen = row["first_seen"]
    if isinstance(first_seen, str):
        first_seen = datetime.fromisoformat(first_seen)
    elapsed = now - first_seen

    if (
        seen_count >= OBSERVE_MIN_COUNT
        and elapsed >= timedelta(hours=OBSERVE_MIN_HOURS)
        and not risky
    ):
        new_status = "ACCEPTED"
        reason = "3회 이상·1시간 이상 정상 관찰되어 Endpoint 기준선으로 승인"
    else:
        new_status = "OBSERVING"
        reason = (
            f"Endpoint 정상 여부 관찰 중 "
            f"({seen_count}/{OBSERVE_MIN_COUNT}회, "
            f"{elapsed.total_seconds() / 3600:.1f}시간)"
        )

    db.execute(
        text("""
            UPDATE behavior_change_observations
               SET status=:status,
                   last_seen=:now,
                   seen_count=:seen_count,
                   max_risk_score=:max_risk_score,
                   risky_context_count=risky_context_count + :risky_inc,
                   decision_reason=:reason
             WHERE id=:id
        """),
        {
            "status": new_status,
            "now": now,
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
    return {
        "type": change_type,
        "value": change_value,
        "status": new_status,
        "reason": reason,
    }


def observe_endpoint_changes(db, event, risk_score, reference_time=None):
    now = reference_time or getattr(event, "timestamp", None) or datetime.now()
    user = str(getattr(event, "user", "") or "").strip()
    if not user:
        return []

    results = []
    for change_type, value in (
        ("ENDPOINT_NETWORK", getattr(event, "endpoint_network", None)),
        ("AGENT_ID", getattr(event, "agent_id", None)),
    ):
        value = str(value or "").strip()
        if not value:
            continue
        result = _observe_one(
            db=db,
            user=user,
            change_type=change_type,
            change_value=value,
            risk_score=risk_score,
            now=now,
        )
        if result:
            results.append(result)
    return results


def get_endpoint_event_context(db, event_id):
    ensure_endpoint_tables(db)
    row = db.execute(
        text("""
            SELECT event_id, user, agent_id, endpoint_ip,
                   endpoint_network, host, observed_at
              FROM endpoint_event_context
             WHERE event_id=:event_id
        """),
        {"event_id": event_id},
    ).mappings().first()
    return dict(row) if row else None


def get_endpoint_profile(db, user):
    ensure_endpoint_tables(db)
    _ensure_behavior_table(db)

    current = db.execute(
        text("""
            SELECT event_id, user, agent_id, endpoint_ip,
                   endpoint_network, host, observed_at
              FROM endpoint_event_context
             WHERE user=:user
             ORDER BY observed_at DESC, id DESC
             LIMIT 1
        """),
        {"user": user},
    ).mappings().first()

    observations = db.execute(
        text("""
            SELECT id, change_type, change_value, status,
                   first_seen, last_seen, seen_count,
                   max_risk_score, risky_context_count,
                   decision_reason, manual_override, manual_note, decided_at
              FROM behavior_change_observations
             WHERE user=:user
               AND change_type IN ('ENDPOINT_NETWORK', 'AGENT_ID')
             ORDER BY last_seen DESC
        """),
        {"user": user},
    ).mappings().all()

    return {
        "user": user,
        "current": dict(current) if current else None,
        "accepted_networks": sorted(_accepted_values(db, user, "ENDPOINT_NETWORK")),
        "accepted_agents": sorted(_accepted_values(db, user, "AGENT_ID")),
        "observations": [dict(row) for row in observations],
    }
