from datetime import datetime
from sqlalchemy import text

from server.database import SessionLocal
from server.main import EventCreate, process_security_event
from server.risk_explanation_engine import get_risk_explanation

TEST_USER = "__risk_receipt_demo__"

db = SessionLocal()
try:
    db.execute(text("DELETE FROM event_risk_explanations WHERE event_id IN (SELECT id FROM security_events WHERE user=:u)"), {"u": TEST_USER})
    db.execute(text("DELETE FROM security_events WHERE user=:u"), {"u": TEST_USER})
    db.commit()

    event = EventCreate(
        user=TEST_USER,
        event_type="usb_connected",
        timestamp=datetime.now().replace(hour=23, minute=30, second=0, microsecond=0),
        source="risk_receipt_test",
        source_ip="10.99.99.7",
        login_success=1,
        login_fail_count=0,
        file_access_count=0,
        usb_connected=1,
        device_name="Receipt Test USB",
        device_id="RECEIPT-USB-01",
        process_name="powershell.exe",
    )

    result = process_security_event(event, db, perf_logging=False)
    explanation = get_risk_explanation(db, result["event_id"])

    print("=" * 72)
    print("Explainable Risk Score - 점수 영수증 테스트")
    print("=" * 72)
    print(explanation.get("plain_summary"))
    print()
    print("[점수 영수증]")
    for line in explanation.get("score_receipt", []):
        print(" -", line)
    print()
    print("[판단]")
    print(explanation.get("decision_text"))
    print()
    print("[구성요소]")
    for item in explanation.get("components", []):
        print(f" - {item['label']}: {item.get('plain_explanation')}")
    print()
    print("[성공] 점수 영수증 생성 완료")
finally:
    db.close()
