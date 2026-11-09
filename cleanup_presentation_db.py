import argparse
from sqlalchemy import text

from server.database import SessionLocal


TEST_USERS = [
    "__perf_verify__",
    "__integration_verify__",
    "__sequence_verify__",
    "__change_verify_demo__",
    "__change_verify_reject_demo__",
    "__full_detection_test__",
    "__risk_receipt_demo__",
]

KEEP_USERS = {
    "siem_demo",
    "user01",
    "user02",
    "user03",
    "user04",
    "admin01",
}


def table_exists(db, table_name):
    row = db.execute(
        text("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
              AND name=:name
        """),
        {"name": table_name},
    ).first()

    return row is not None


def scalar_count(db, sql, params=None):
    try:
        return int(
            db.execute(
                text(sql),
                params or {},
            ).scalar()
            or 0
        )
    except Exception:
        db.rollback()
        return 0


def count_for_user(db, table_name, username):
    if not table_exists(db, table_name):
        return 0

    columns = {
        row["name"]
        for row in db.execute(
            text(f"PRAGMA table_info({table_name})")
        ).mappings().all()
    }

    if "user" in columns:
        return scalar_count(
            db,
            f"SELECT COUNT(*) FROM {table_name} WHERE user=:user",
            {"user": username},
        )

    if table_name == "monitored_users" and "username" in columns:
        return scalar_count(
            db,
            "SELECT COUNT(*) FROM monitored_users WHERE username=:user",
            {"user": username},
        )

    return 0


def fetch_ids(db, sql, params):
    return [
        int(row[0])
        for row in db.execute(
            text(sql),
            params,
        ).all()
    ]


def delete_by_ids(db, table_name, column_name, ids):
    if not ids or not table_exists(db, table_name):
        return 0

    placeholders = ", ".join(
        f":id_{index}"
        for index in range(len(ids))
    )

    params = {
        f"id_{index}": value
        for index, value in enumerate(ids)
    }

    result = db.execute(
        text(
            f"DELETE FROM {table_name} "
            f"WHERE {column_name} IN ({placeholders})"
        ),
        params,
    )

    return int(result.rowcount or 0)


def delete_direct_user_rows(db, table_name, username):
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


def cleanup_user(db, username):
    if username in KEEP_USERS:
        raise RuntimeError(
            f"보호 사용자 삭제 차단: {username}"
        )

    deleted = {}

    # -----------------------------------------
    # 부모 레코드 ID 확보
    # -----------------------------------------
    event_ids = []

    if table_exists(db, "security_events"):
        event_ids = fetch_ids(
            db,
            """
            SELECT id
            FROM security_events
            WHERE user=:user
            """,
            {"user": username},
        )

    incident_ids = []

    if table_exists(db, "security_incidents"):
        incident_ids = fetch_ids(
            db,
            """
            SELECT id
            FROM security_incidents
            WHERE user=:user
            """,
            {"user": username},
        )

    # -----------------------------------------
    # 자식 테이블부터 삭제
    # -----------------------------------------
    deleted["event_risk_explanations"] = (
        delete_by_ids(
            db,
            "event_risk_explanations",
            "event_id",
            event_ids,
        )
    )

    deleted["response_playbook_executions"] = (
        delete_by_ids(
            db,
            "response_playbook_executions",
            "incident_id",
            incident_ids,
        )
    )

    # event_context에는 user가 있으므로 직접 사용자 기준 삭제
    deleted["event_context"] = delete_direct_user_rows(
        db,
        "event_context",
        username,
    )

    deleted["behavior_change_observations"] = (
        delete_direct_user_rows(
            db,
            "behavior_change_observations",
            username,
        )
    )

    deleted["security_incidents"] = (
        delete_direct_user_rows(
            db,
            "security_incidents",
            username,
        )
    )

    deleted["security_events"] = (
        delete_direct_user_rows(
            db,
            "security_events",
            username,
        )
    )

    # monitored_users는 이미 API에서 지워졌을 수도 있음
    if table_exists(db, "monitored_users"):
        result = db.execute(
            text("""
                DELETE FROM monitored_users
                WHERE username=:user
            """),
            {"user": username},
        )
        deleted["monitored_users"] = int(
            result.rowcount or 0
        )
    else:
        deleted["monitored_users"] = 0

    return deleted


def print_preview(db):
    print("=" * 78)
    print("SENTINEL 발표 DB 정리 미리보기")
    print("=" * 78)

    tables = [
        "security_events",
        "event_context",
        "behavior_change_observations",
        "security_incidents",
        "monitored_users",
    ]

    total = 0

    for username in TEST_USERS:
        print()
        print(f"[{username}]")

        user_total = 0

        for table in tables:
            count = count_for_user(
                db,
                table,
                username,
            )

            user_total += count

            print(
                f"  {table:<30} {count:>6}"
            )

        print(
            f"  {'삭제 대상 합계':<30} {user_total:>6}"
        )

        total += user_total

    print()
    print("-" * 78)
    print(f"주요 테이블 기준 삭제 대상 합계: {total:,}")
    print("-" * 78)
    print(
        "보호 사용자: "
        + ", ".join(sorted(KEEP_USERS))
    )
    print("=" * 78)


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL 발표용 DB 테스트 데이터 정리"
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="실제 삭제 실행. 생략하면 미리보기만 수행",
    )

    args = parser.parse_args()

    db = SessionLocal()

    try:
        print_preview(db)

        if not args.apply:
            print()
            print(
                "[미리보기 완료] 실제 삭제는 수행하지 않았습니다."
            )
            print(
                "삭제하려면:"
            )
            print(
                "  python cleanup_presentation_db.py --apply"
            )
            return

        print()
        print("=" * 78)
        print("[삭제 실행]")
        print("=" * 78)

        grand_total = 0

        for username in TEST_USERS:
            deleted = cleanup_user(
                db,
                username,
            )

            subtotal = sum(
                deleted.values()
            )
            grand_total += subtotal

            print()
            print(f"[{username}] 삭제 {subtotal}건")

            for table, count in deleted.items():
                if count:
                    print(
                        f"  - {table}: {count}"
                    )

        db.commit()

        print()
        print("=" * 78)
        print(
            f"[완료] 총 {grand_total:,}건 삭제"
        )
        print("=" * 78)
        print(
            "siem_demo / user01~04 / admin01 데이터는 "
            "보호되어 삭제하지 않았습니다."
        )
        print(
            "Streamlit 대시보드는 3초 자동 갱신 후 "
            "정리된 데이터를 반영합니다."
        )

    except Exception as error:
        db.rollback()

        print()
        print("[오류] 정리 중 롤백했습니다.")
        print(type(error).__name__, error)
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
