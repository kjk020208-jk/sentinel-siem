from datetime import datetime, timedelta
from sqlalchemy import text

from server.database import SessionLocal
from server.main import EventCreate, process_security_event


VIRTUAL_USERS = {
    "user01": {
        "ip": "10.10.10.21",
        "host": "DEV-PC-01",
        "processes": ["Code.exe", "git.exe", "chrome.exe", "notepad.exe"],
        "files": ["project_notes.txt", "requirements.txt"],
    },
    "user02": {
        "ip": "10.10.20.31",
        "host": "HR-PC-01",
        "processes": ["EXCEL.EXE", "WINWORD.EXE", "chrome.exe", "AcroRd32.exe"],
        "files": ["employee_schedule.xlsx", "policy_document.docx"],
    },
    "user03": {
        "ip": "10.10.30.41",
        "host": "FIN-PC-01",
        "processes": ["EXCEL.EXE", "AcroRd32.exe", "chrome.exe", "notepad.exe"],
        "files": ["monthly_report.xlsx", "budget_plan.xlsx"],
    },
    "user04": {
        "ip": "10.10.40.51",
        "host": "SALES-PC-01",
        "processes": ["OUTLOOK.EXE", "chrome.exe", "POWERPNT.EXE", "EXCEL.EXE"],
        "files": ["sales_plan.pptx", "customer_schedule.xlsx"],
    },
    "admin01": {
        "ip": "10.10.50.10",
        "host": "ADMIN-PC-01",
        "processes": ["mmc.exe", "mstsc.exe", "cmd.exe", "notepad.exe"],
        "files": ["maintenance_log.txt", "asset_list.xlsx"],
    },
}

REAL_DEMO_USER = "siem_demo"
OPTIONAL_REAL_USER = "김재경"


def table_exists(db, name):
    return db.execute(
        text("""
            SELECT 1 FROM sqlite_master
            WHERE type='table' AND name=:name
        """),
        {"name": name},
    ).first() is not None


def ids_for_user(db, table_name, username):
    if not table_exists(db, table_name):
        return []
    return [
        int(row[0])
        for row in db.execute(
            text(f"SELECT id FROM {table_name} WHERE user=:user"),
            {"user": username},
        ).all()
    ]


def delete_ids(db, table_name, column_name, ids):
    if not ids or not table_exists(db, table_name):
        return 0

    marks = ",".join(f":v{i}" for i in range(len(ids)))
    params = {f"v{i}": value for i, value in enumerate(ids)}
    result = db.execute(
        text(
            f"DELETE FROM {table_name} "
            f"WHERE {column_name} IN ({marks})"
        ),
        params,
    )
    return int(result.rowcount or 0)


def delete_user_rows(db, table_name, username):
    if not table_exists(db, table_name):
        return 0

    cols = {
        row["name"]
        for row in db.execute(
            text(f"PRAGMA table_info({table_name})")
        ).mappings().all()
    }
    if "user" not in cols:
        return 0

    result = db.execute(
        text(f"DELETE FROM {table_name} WHERE user=:user"),
        {"user": username},
    )
    return int(result.rowcount or 0)


def reset_user_analysis(db, username):
    event_ids = ids_for_user(db, "security_events", username)
    incident_ids = ids_for_user(db, "security_incidents", username)

    deleted = 0
    deleted += delete_ids(
        db, "event_risk_explanations", "event_id", event_ids
    )
    deleted += delete_ids(
        db, "response_playbook_executions", "incident_id", incident_ids
    )
    deleted += delete_user_rows(db, "event_context", username)
    deleted += delete_user_rows(
        db, "behavior_change_observations", username
    )
    deleted += delete_user_rows(db, "security_incidents", username)
    deleted += delete_user_rows(db, "security_events", username)
    return deleted


def ensure_active(db, username):
    if not table_exists(db, "monitored_users"):
        return

    db.execute(
        text("""
            UPDATE monitored_users
               SET monitoring_enabled=1
             WHERE username=:username
        """),
        {"username": username},
    )


def disable_old_real_user(db):
    if not table_exists(db, "monitored_users"):
        return

    db.execute(
        text("""
            UPDATE monitored_users
               SET monitoring_enabled=0
             WHERE username=:username
        """),
        {"username": OPTIONAL_REAL_USER},
    )


def create_event(username, timestamp, event_kind, value):
    cfg = VIRTUAL_USERS[username]

    common = dict(
        user=username,
        timestamp=timestamp,
        source="presentation_baseline_v2",
        source_ip=cfg["ip"],
        host=cfg["host"],
        workstation_name=cfg["host"],
        logon_type="2",
        login_success=1,
        login_fail_count=0,
        usb_connected=0,
    )

    if event_kind == "process":
        return EventCreate(
            event_type="process_execution",
            process_name=value,
            command_line=value,
            parent_process="explorer.exe",
            file_access_count=0,
            **common,
        )

    return EventCreate(
        event_type="file_access",
        file_name=value,
        file_path=f"C:\\PRESENTATION_NORMAL\\{value}",
        file_grade="일반",
        file_access_count=1,
        **common,
    )


def seed_user(db, username):
    cfg = VIRTUAL_USERS[username]

    # 최근 3개 평일처럼 보이는 정상 업무 이력.
    # 각 행동은 1시간 이상 간격으로 반복되어
    # Behavior Change의 3회 + 1시간 조건을 충족한다.
    today = datetime.now().replace(
        hour=9, minute=0, second=0, microsecond=0
    )

    day_offsets = [3, 2, 1]
    hours = [9, 10, 11, 13, 14, 15, 16, 17]

    generated = 0

    for day_index, days_ago in enumerate(day_offsets):
        day_base = today - timedelta(days=days_ago)

        for slot, hour in enumerate(hours):
            timestamp = day_base.replace(
                hour=hour,
                minute=(slot * 7 + day_index * 3) % 50,
            )

            # 프로세스는 4종을 반복하여 각 항목이 여러 번 관찰되게 한다.
            process_name = cfg["processes"][slot % len(cfg["processes"])]

            event = create_event(
                username,
                timestamp,
                "process",
                process_name,
            )

            process_security_event(
                event,
                db,
                perf_logging=False,
            )
            generated += 1

            # 하루 2번 정도 일반 파일 접근 추가.
            if slot in (2, 5):
                file_name = cfg["files"][
                    (day_index + slot) % len(cfg["files"])
                ]
                file_event = create_event(
                    username,
                    timestamp + timedelta(minutes=4),
                    "file",
                    file_name,
                )
                process_security_event(
                    file_event,
                    db,
                    perf_logging=False,
                )
                generated += 1

    return generated


def behavior_summary(db, username):
    if not table_exists(db, "behavior_change_observations"):
        return {}

    rows = db.execute(
        text("""
            SELECT status, COUNT(*) AS cnt
            FROM behavior_change_observations
            WHERE user=:user
            GROUP BY status
        """),
        {"user": username},
    ).mappings().all()

    return {
        str(row["status"]): int(row["cnt"])
        for row in rows
    }


def main():
    db = SessionLocal()

    try:
        print("=" * 76)
        print("SENTINEL FINAL PRESENTATION DATA PREP")
        print("=" * 76)
        print("CERT 100K 사용자 데이터는 삭제하지 않습니다.")
        print()

        targets = list(VIRTUAL_USERS) + [REAL_DEMO_USER]

        print("[1] 발표용 6명 기존 분석 데이터 초기화")
        for username in targets:
            deleted = reset_user_analysis(db, username)
            ensure_active(db, username)
            print(f"  {username:<12} 삭제 {deleted}건")

        # 기존 실제 개인 계정은 데이터는 보존하되,
        # 발표용 운영 화면에서 빠지도록 모니터링만 비활성화.
        disable_old_real_user(db)
        db.commit()

        print()
        print("[2] 가상 사용자 5명 정상 업무 Baseline 재생성")
        for username in VIRTUAL_USERS:
            count = seed_user(db, username)
            print(f"  {username:<12} 정상 이벤트 {count}건")

        db.commit()

        print()
        print("[3] Behavior Change 상태 확인")
        for username in VIRTUAL_USERS:
            summary = behavior_summary(db, username)
            print(
                f"  {username:<12} "
                f"ACCEPTED={summary.get('ACCEPTED', 0)} / "
                f"OBSERVING={summary.get('OBSERVING', 0)} / "
                f"REJECTED={summary.get('REJECTED', 0)}"
            )

        print()
        print("=" * 76)
        print("완료")
        print("=" * 76)
        print("남겨둔 실제 시연 사용자: siem_demo")
        print("siem_demo에는 가상 이벤트를 넣지 않았습니다.")
        print("김재경 계정의 과거 데이터는 삭제하지 않고 모니터링만 비활성화했습니다.")
        print("CERT 100K 데이터는 사용자 이름 기준으로 전혀 건드리지 않았습니다.")
        print()
        print("다음 단계:")
        print("  1) 대시보드 새로고침")
        print("  2) 가상 사용자 Baseline/ACCEPTED 확인")
        print("  3) siem_demo 실제 Windows 정상 행동 수집")
        print("  4) 공격 시나리오 녹화")

    except Exception as error:
        db.rollback()
        print()
        print("[오류] 작업 중 오류가 발생했습니다.")
        print(
            "일부 엔진이 내부 commit을 수행할 수 있으므로 "
            "수정 후 이 스크립트를 다시 실행하면 "
            "발표용 6명을 다시 초기화하고 재구성합니다."
        )
        print(type(error).__name__, error)
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
