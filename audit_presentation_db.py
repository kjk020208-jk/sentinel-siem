from sqlalchemy import text
from server.database import SessionLocal


TABLES = [
    "security_events",
    "event_context",
    "behavior_change_observations",
    "security_incidents",
    "monitored_users",
]


def table_exists(db, table_name):
    return db.execute(
        text("""
            SELECT 1
            FROM sqlite_master
            WHERE type='table' AND name=:name
        """),
        {"name": table_name},
    ).first() is not None


def columns(db, table_name):
    return {
        row["name"]
        for row in db.execute(
            text(f"PRAGMA table_info({table_name})")
        ).mappings().all()
    }


db = SessionLocal()

try:
    print("=" * 88)
    print("SENTINEL 발표 전 사용자/테이블 감사")
    print("=" * 88)

    # ------------------------------------------------------------
    # SQLite 전체 테이블 및 CERT 관련 테이블
    # ------------------------------------------------------------
    all_tables = [
        row[0]
        for row in db.execute(
            text("""
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                ORDER BY name
            """)
        ).all()
    ]

    cert_tables = [
        name for name in all_tables
        if "cert" in name.lower()
        or "100k" in name.lower()
        or "dataset" in name.lower()
    ]

    print()
    print("[CERT / Dataset 관련 테이블 후보]")
    if cert_tables:
        for name in cert_tables:
            count = db.execute(
                text(f"SELECT COUNT(*) FROM {name}")
            ).scalar() or 0
            print(f"  {name:<40} {int(count):>10,} rows")
    else:
        print("  이름 기준 후보 테이블 없음")

    # ------------------------------------------------------------
    # Monitored users
    # ------------------------------------------------------------
    if table_exists(db, "monitored_users"):
        cols = columns(db, "monitored_users")
        username_col = (
            "username" if "username" in cols else "user"
        )

        print()
        print("[등록 모니터링 사용자]")
        rows = db.execute(
            text(
                f"""
                SELECT {username_col}
                FROM monitored_users
                ORDER BY {username_col}
                """
            )
        ).all()

        for row in rows:
            print(f"  {row[0]}")

        print(f"  총 {len(rows)}명")

    # ------------------------------------------------------------
    # Event users
    # ------------------------------------------------------------
    if table_exists(db, "security_events"):
        print()
        print("[security_events 사용자별 건수]")

        rows = db.execute(
            text("""
                SELECT user,
                       COUNT(*) AS cnt,
                       SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) AS critical,
                       SUM(CASE WHEN risk_level='HIGH' THEN 1 ELSE 0 END) AS high,
                       ROUND(AVG(COALESCE(risk_score, 0)), 2) AS avg_risk,
                       ROUND(MAX(COALESCE(risk_score, 0)), 2) AS max_risk
                FROM security_events
                GROUP BY user
                ORDER BY cnt DESC, user
            """)
        ).mappings().all()

        print(
            f"{'사용자':<28}"
            f"{'이벤트':>9}"
            f"{'HIGH':>8}"
            f"{'CRIT':>8}"
            f"{'평균Risk':>12}"
            f"{'최대Risk':>12}"
        )
        print("-" * 88)

        for row in rows:
            print(
                f"{str(row['user']):<28}"
                f"{int(row['cnt'] or 0):>9}"
                f"{int(row['high'] or 0):>8}"
                f"{int(row['critical'] or 0):>8}"
                f"{float(row['avg_risk'] or 0):>12.2f}"
                f"{float(row['max_risk'] or 0):>12.2f}"
            )

        print("-" * 88)
        print(f"security_events 고유 사용자: {len(rows)}명")

    # ------------------------------------------------------------
    # Incident users
    # ------------------------------------------------------------
    if table_exists(db, "security_incidents"):
        print()
        print("[현재 Incident 사용자]")
        rows = db.execute(
            text("""
                SELECT user,
                       COUNT(*) AS cnt,
                       SUM(CASE WHEN status='OPEN' THEN 1 ELSE 0 END) AS open_cnt,
                       SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical_cnt
                FROM security_incidents
                GROUP BY user
                ORDER BY cnt DESC, user
            """)
        ).mappings().all()

        if rows:
            for row in rows:
                print(
                    f"  {row['user']}: "
                    f"{int(row['cnt'] or 0)}건 / "
                    f"OPEN {int(row['open_cnt'] or 0)} / "
                    f"CRITICAL {int(row['critical_cnt'] or 0)}"
                )
        else:
            print("  없음")

    print()
    print("=" * 88)
    print("이 스크립트는 조회만 하며 DB를 변경하지 않습니다.")
    print("=" * 88)

finally:
    db.close()
