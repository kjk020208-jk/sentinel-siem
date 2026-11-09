from datetime import datetime, timedelta
from sqlalchemy import text

from server.database import SessionLocal
from server.main import EventCreate, process_security_event
from server.change_verification_engine import get_behavior_changes

TEST_USER = "__change_verify_demo__"
TEST_IP = "10.250.250.77"
TEST_PROCESS = "change_verify_demo.exe"

db = SessionLocal()

try:
    # 이전 테스트 흔적 정리
    db.execute(
        text("DELETE FROM behavior_change_observations WHERE user=:user"),
        {"user": TEST_USER},
    )
    db.execute(
        text("DELETE FROM security_events WHERE user=:user"),
        {"user": TEST_USER},
    )
    db.commit()

    base = datetime.now().replace(hour=12, minute=0, second=0, microsecond=0)

    test_times = [
        base,
        base + timedelta(minutes=30),
        base + timedelta(minutes=70),
    ]

    print("=" * 72)
    print("Change Verification Flow Test")
    print("=" * 72)

    for index, ts in enumerate(test_times, start=1):
        event = EventCreate(
            user=TEST_USER,
            event_type="process_execution",
            timestamp=ts,
            source="change_verification_test",
            source_ip=TEST_IP,
            login_success=1,
            login_fail_count=0,
            file_access_count=0,
            usb_connected=0,
            process_name=TEST_PROCESS,
        )

        result = process_security_event(
            event,
            db,
            perf_logging=False,
        )

        changes = get_behavior_changes(db, user=TEST_USER)

        print()
        print(f"[{index}회차]")
        print(f"timestamp   : {ts}")
        print(f"risk_score  : {result['risk_score']}")
        print(f"risk_level  : {result['risk_level']}")

        for change in changes:
            print(
                f"{change['change_type']}={change['change_value']} | "
                f"status={change['status']} | "
                f"seen={change['seen_count']} | "
                f"reason={change['decision_reason']}"
            )

    print()
    print("=" * 72)
    print("[최종 상태]")
    final_changes = get_behavior_changes(db, user=TEST_USER)

    for change in final_changes:
        print(
            f"{change['change_type']}={change['change_value']} -> "
            f"{change['status']}"
        )

    print()
    if final_changes and all(
        c["status"] == "ACCEPTED"
        for c in final_changes
    ):
        print("[성공] OBSERVING -> ACCEPTED 검증 완료")
    else:
        print("[확인 필요] 일부 항목이 아직 ACCEPTED가 아닙니다.")

finally:
    db.close()
