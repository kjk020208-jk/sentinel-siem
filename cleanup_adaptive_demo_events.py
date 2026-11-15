from server.database import SessionLocal
from server.models import SecurityEvent

DEMO_USERS = ["office_demo", "flex_demo"]

def main():
    db = SessionLocal()
    try:
        before = db.query(SecurityEvent).filter(
            SecurityEvent.user.in_(DEMO_USERS)
        ).count()

        deleted = db.query(SecurityEvent).filter(
            SecurityEvent.user.in_(DEMO_USERS)
        ).delete(synchronize_session=False)

        db.commit()

        remaining = db.query(SecurityEvent).filter(
            SecurityEvent.user.in_(DEMO_USERS)
        ).count()

        print("=" * 72)
        print("SENTINEL Adaptive Demo temporary data cleanup")
        print("=" * 72)
        print(f"삭제 전 비교용 이벤트 : {before:,}건")
        print(f"삭제된 비교용 이벤트  : {deleted:,}건")
        print(f"삭제 후 남은 이벤트   : {remaining:,}건")
        print()
        print("[OK] office_demo / flex_demo 비교용 이벤트만 제거했습니다.")
        print("[OK] 15명 전시 사용자와 30,000건 전시 데이터는 건드리지 않았습니다.")
    finally:
        db.close()

if __name__ == "__main__":
    main()
