from server.database import SessionLocal
from server.change_verification_engine import ensure_change_table, get_behavior_changes

db = SessionLocal()
try:
    ensure_change_table(db)
    rows = get_behavior_changes(db)
    print("[OK] behavior_change_observations 테이블 준비 완료")
    print("[INFO] 현재 관찰 항목 수:", len(rows))
finally:
    db.close()
