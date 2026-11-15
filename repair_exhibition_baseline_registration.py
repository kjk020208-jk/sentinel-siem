from datetime import datetime, timedelta

from server.database import SessionLocal
from server.models import MonitoredUser

USERS = [
    "dev01",
    "dev02",
    "dev03",
    "dev04",
    "office01",
    "office02",
    "finance01",
    "finance02",
    "sales01",
    "design01",
    "plan01",
    "admin01",
    "security01",
    "manager01",
]

HISTORY_DAYS = 90

db = SessionLocal()

try:
    target_time = (
        datetime.now()
        - timedelta(days=HISTORY_DAYS)
    ).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )

    print("=" * 72)
    print("SENTINEL Exhibition Baseline Registration-Time Repair")
    print("=" * 72)
    print("대상: 전시용 가상 사용자 14명")
    print("siem_demo는 변경하지 않습니다.")
    print(f"보정 등록 시각: {target_time}")
    print()

    updated = 0

    for username in USERS:
        user = (
            db.query(MonitoredUser)
            .filter(MonitoredUser.username == username)
            .first()
        )

        if user is None:
            print(f"[SKIP] {username:<12} 등록 사용자 없음")
            continue

        old = user.created_at

        user.created_at = target_time
        user.monitoring_enabled = 1

        updated += 1

        print(
            f"[OK]   {username:<12} "
            f"{old} -> {target_time}"
        )

    db.commit()

    print()
    print("=" * 72)
    print(f"완료: {updated}명 보정")
    print("=" * 72)
    print()
    print("이제 Behavior Profile은 최근 30일 LOW 이벤트를")
    print("정상 학습 데이터로 인식할 수 있습니다.")
    print()
    print("확인:")
    print("  대시보드 -> 사용자 행동 분석 -> 사용자 재선택")
    print("  또는 브라우저 Ctrl+F5")

except Exception:
    db.rollback()
    raise

finally:
    db.close()
