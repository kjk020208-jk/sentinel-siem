from datetime import datetime, timedelta

from server.database import SessionLocal
from server.models import SecurityEvent
from server.baseline_engine import (
    analyze_user_baseline,
    get_user_behavior_profile
)


TEST_USER = "adaptive_test_user"
NORMAL_IP = "192.168.56.101"


def create_normal_behavior(db):
    print("\n[1] 정상 행동 학습 데이터 생성")

    # 기존 테스트 사용자 데이터만 삭제
    db.query(SecurityEvent).filter(
        SecurityEvent.user == TEST_USER
    ).delete()

    db.commit()

    now = datetime.now()

    file_event_count = 0
    process_event_count = 0

    # 최근 20일 동안 평일 업무 패턴 생성
    for days_ago in range(1, 21):
        target_date = now - timedelta(
            days=days_ago
        )

        # 월~금만 정상 업무일로 사용
        if target_date.weekday() >= 5:
            continue

        # 평소 업무 시간
        for hour in [
            9,
            10,
            11,
            13,
            14,
            15,
            16,
            17
        ]:
            timestamp = target_date.replace(
                hour=hour,
                minute=0,
                second=0,
                microsecond=0
            )

            # 평소 사용하는 프로세스
            process_name = (
                "WINWORD.EXE"
                if file_event_count % 2 == 0
                else "EXCEL.EXE"
            )

            # --------------------------------
            # 정상 파일 접근 이벤트
            # --------------------------------

            file_event = SecurityEvent(
                user=TEST_USER,
                event_type="file_access",
                timestamp=timestamp,
                source_ip=NORMAL_IP,
                login_success=1,
                login_fail_count=0,
                file_name="normal_document.docx",
                file_grade="일반",
                file_access_count=3,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons="정상 파일 접근 학습 데이터"
            )

            db.add(
                file_event
            )

            file_event_count += 1

            # --------------------------------
            # 정상 프로세스 실행 이벤트
            # --------------------------------

            process_event = SecurityEvent(
                user=TEST_USER,
                event_type="process_execution",
                timestamp=timestamp + timedelta(
                    minutes=1
                ),
                source_ip=NORMAL_IP,
                login_success=1,
                login_fail_count=0,
                file_name=None,
                file_grade=None,
                file_access_count=0,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons="정상 프로세스 학습 데이터"
            )

            db.add(
                process_event
            )

            process_event_count += 1

    db.commit()

    print(
        f"정상 파일 접근 이벤트 "
        f"{file_event_count}개 생성"
    )

    print(
        f"정상 프로세스 이벤트 "
        f"{process_event_count}개 생성"
    )

    print(
        f"전체 학습 이벤트 "
        f"{file_event_count + process_event_count}개 생성 완료"
    )


def show_profile(db):
    print("\n[2] 학습된 사용자 행동 프로필")

    profile = get_user_behavior_profile(
        db,
        TEST_USER
    )

    for key, value in profile.items():
        print(
            f"{key}: {value}"
        )


def test_normal_behavior(db):
    print("\n[3] 평소와 비슷한 행동 테스트")

    now = datetime.now()

    normal_timestamp = now.replace(
        hour=10,
        minute=0,
        second=0,
        microsecond=0
    )

    score, reasons = analyze_user_baseline(
        db=db,
        user=TEST_USER,
        current_ip=NORMAL_IP,
        current_hour=10,
        current_file_access_count=3,
        current_process_name="WINWORD.EXE",
        current_usb_connected=0,
        current_timestamp=normal_timestamp
    )

    print(
        f"정상 행동 Baseline Score: {score}"
    )

    print("탐지 사유:")

    if reasons:
        for reason in reasons:
            print(
                f"- {reason}"
            )

    else:
        print(
            "- 이상 행동 없음"
        )


def test_abnormal_behavior(db):
    print("\n[4] 평소와 다른 행동 테스트")

    now = datetime.now()

    abnormal_timestamp = now.replace(
        hour=2,
        minute=0,
        second=0,
        microsecond=0
    )

    score, reasons = analyze_user_baseline(
        db=db,
        user=TEST_USER,
        current_ip="203.0.113.77",
        current_hour=2,
        current_file_access_count=30,
        current_process_name="powershell.exe",
        current_usb_connected=1,
        current_timestamp=abnormal_timestamp
    )

    print(
        f"이상 행동 Baseline Score: {score}"
    )

    print("탐지 사유:")

    if reasons:
        for reason in reasons:
            print(
                f"- {reason}"
            )

    else:
        print(
            "- 이상 행동 없음"
        )


def main():
    db = SessionLocal()

    try:
        create_normal_behavior(
            db
        )

        show_profile(
            db
        )

        test_normal_behavior(
            db
        )

        test_abnormal_behavior(
            db
        )

    finally:
        db.close()


if __name__ == "__main__":
    main()