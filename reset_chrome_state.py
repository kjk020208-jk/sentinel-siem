from sqlalchemy import text
from server.database import SessionLocal

USER = "김재경"
PROCESS = "chrome.exe"

db = SessionLocal()

try:
    rows = db.execute(
        text("""
            SELECT id, user, change_type, change_value, status, decision_reason
            FROM behavior_change_observations
            WHERE user=:user
              AND change_type='PROCESS'
              AND lower(change_value)=:process
        """),
        {
            "user": USER,
            "process": PROCESS,
        },
    ).mappings().all()

    print("=" * 72)
    print("[기존 Chrome 행동 변화 기록]")
    print("=" * 72)

    if not rows:
        print("대상 기록 없음")
    else:
        for row in rows:
            print(
                f"id={row['id']} | "
                f"{row['change_type']}={row['change_value']} | "
                f"{row['status']} | "
                f"{row['decision_reason']}"
            )

        db.execute(
            text("""
                DELETE FROM behavior_change_observations
                WHERE user=:user
                  AND change_type='PROCESS'
                  AND lower(change_value)=:process
            """),
            {
                "user": USER,
                "process": PROCESS,
            },
        )
        db.commit()

        print()
        print("[완료] 김재경 / chrome.exe 기존 행동 변화 판정 기록 삭제")
        print("[안내] 과거 SecurityEvent 로그는 삭제하지 않았습니다.")
        print("[안내] 다음 Chrome 이벤트부터 수정된 현재 로직으로 다시 판정됩니다.")

finally:
    db.close()
