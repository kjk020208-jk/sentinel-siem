from datetime import datetime, timedelta
from sqlalchemy import text

from server.database import SessionLocal
from server.main import EventCreate, process_security_event
from server.change_verification_engine import get_behavior_changes

TEST_USER = "__change_verify_reject_demo__"
TEST_IP = "10.250.250.88"
TEST_PROCESS = "reject_verify_demo.exe"
TEST_DEVICE = "USB-REJECT-DEMO-01"

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

    print("=" * 72)
    print("Change Verification Reject Flow Test")
    print("=" * 72)

    # 1회차: 새 IP / 프로세스 -> OBSERVING
    event1 = EventCreate(
        user=TEST_USER,
        event_type="process_execution",
        timestamp=base,
        source="change_verification_reject_test",
        source_ip=TEST_IP,
        login_success=1,
        login_fail_count=0,
        file_access_count=0,
        usb_connected=0,
        process_name=TEST_PROCESS,
    )

    result1 = process_security_event(
        event1,
        db,
        perf_logging=False,
    )

    print()
    print("[1회차 - 새 행동]")
    print(f"risk_score : {result1['risk_score']}")
    print(f"risk_level : {result1['risk_level']}")

    changes1 = get_behavior_changes(db, user=TEST_USER)
    for change in changes1:
        print(
            f"{change['change_type']}={change['change_value']} | "
            f"status={change['status']} | "
            f"seen={change['seen_count']} | "
            f"reason={change['decision_reason']}"
        )

    # 2회차: 같은 IP/프로세스 + USB 연결 -> 강한 위험 맥락
    event2 = EventCreate(
        user=TEST_USER,
        event_type="usb_connected",
        timestamp=base + timedelta(minutes=10),
        source="change_verification_reject_test",
        source_ip=TEST_IP,
        login_success=1,
        login_fail_count=0,
        file_access_count=0,
        usb_connected=1,
        device_name="Reject Demo USB",
        device_id=TEST_DEVICE,
        process_name=TEST_PROCESS,
    )

    result2 = process_security_event(
        event2,
        db,
        perf_logging=False,
    )

    print()
    print("[2회차 - 위험 맥락 추가]")
    print(f"risk_score : {result2['risk_score']}")
    print(f"risk_level : {result2['risk_level']}")

    changes2 = get_behavior_changes(db, user=TEST_USER)
    for change in changes2:
        print(
            f"{change['change_type']}={change['change_value']} | "
            f"status={change['status']} | "
            f"seen={change['seen_count']} | "
            f"reason={change['decision_reason']}"
        )

    print()
    print("=" * 72)
    print("[최종 상태]")

    rejected = 0
    for change in changes2:
        print(
            f"{change['change_type']}={change['change_value']} -> "
            f"{change['status']}"
        )
        if change["status"] == "REJECTED":
            rejected += 1

    print()
    if rejected >= 2:
        print("[성공] OBSERVING -> REJECTED 검증 완료")
    else:
        print("[확인 필요] REJECTED 전환이 충분히 발생하지 않았습니다.")

finally:
    db.close()
