from sqlalchemy import text
from server.database import SessionLocal

TARGET_USER = "siem_demo"


def table_exists(db, name):
    return db.execute(
        text("""
            SELECT 1
            FROM sqlite_master
            WHERE type='table' AND name=:name
        """),
        {"name": name},
    ).first() is not None


def get_ids(db, table_name, username):
    if not table_exists(db, table_name):
        return []

    return [
        int(row[0])
        for row in db.execute(
            text(f"""
                SELECT id
                FROM {table_name}
                WHERE user=:user
            """),
            {"user": username},
        ).all()
    ]


def delete_by_ids(db, table_name, column_name, ids):
    if not ids or not table_exists(db, table_name):
        return 0

    placeholders = ", ".join(
        f":id_{i}" for i in range(len(ids))
    )
    params = {
        f"id_{i}": value
        for i, value in enumerate(ids)
    }

    result = db.execute(
        text(
            f"DELETE FROM {table_name} "
            f"WHERE {column_name} IN ({placeholders})"
        ),
        params,
    )

    return int(result.rowcount or 0)


def delete_user_rows(db, table_name, username):
    if not table_exists(db, table_name):
        return 0

    columns = {
        row["name"]
        for row in db.execute(
            text(f"PRAGMA table_info({table_name})")
        ).mappings().all()
    }

    if "user" not in columns:
        return 0

    result = db.execute(
        text(
            f"DELETE FROM {table_name} "
            f"WHERE user=:user"
        ),
        {"user": username},
    )

    return int(result.rowcount or 0)


def main():
    db = SessionLocal()

    try:
        event_ids = get_ids(
            db,
            "security_events",
            TARGET_USER,
        )
        incident_ids = get_ids(
            db,
            "security_incidents",
            TARGET_USER,
        )

        deleted = {}

        deleted["event_risk_explanations"] = delete_by_ids(
            db,
            "event_risk_explanations",
            "event_id",
            event_ids,
        )

        deleted["response_playbook_executions"] = delete_by_ids(
            db,
            "response_playbook_executions",
            "incident_id",
            incident_ids,
        )

        deleted["event_context"] = delete_user_rows(
            db,
            "event_context",
            TARGET_USER,
        )

        deleted["behavior_change_observations"] = delete_user_rows(
            db,
            "behavior_change_observations",
            TARGET_USER,
        )

        deleted["security_incidents"] = delete_user_rows(
            db,
            "security_incidents",
            TARGET_USER,
        )

        deleted["security_events"] = delete_user_rows(
            db,
            "security_events",
            TARGET_USER,
        )

        # 모니터링 사용자 등록은 유지하고 활성화
        if table_exists(db, "monitored_users"):
            db.execute(
                text("""
                    UPDATE monitored_users
                       SET monitoring_enabled=1
                     WHERE username=:username
                """),
                {"username": TARGET_USER},
            )

        db.commit()

        total = sum(deleted.values())

        print("=" * 70)
        print("siem_demo 초기화 완료")
        print("=" * 70)

        for table, count in deleted.items():
            if count:
                print(f"{table:<32} {count}")

        print("-" * 70)
        print(f"총 삭제: {total}건")
        print("monitored_users의 siem_demo 등록은 유지했습니다.")
        print("이제 정상 로그인부터 다시 시작하면 됩니다.")
        print("=" * 70)

    except Exception as error:
        db.rollback()
        print("[오류] 롤백했습니다.")
        print(type(error).__name__, error)
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
