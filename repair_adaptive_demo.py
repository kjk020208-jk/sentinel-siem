from server.database import SessionLocal
from server.main import train_adaptive_baseline_demo, compare_adaptive_baseline_demo

def main():
    db = SessionLocal()
    try:
        print("=" * 72)
        print("SENTINEL Adaptive Demo Repair")
        print("=" * 72)
        print()

        print("[1] office_demo / flex_demo 전용 Baseline 재학습")
        result = train_adaptive_baseline_demo(db=db)

        office = result.get("office_demo", {})
        flex = result.get("flex_demo", {})

        print("office_demo:", office.get("created_events"), "events")
        print("flex_demo  :", flex.get("created_events"), "events")

        print()
        print("[2] 동일 행동 비교 검증")
        compare = compare_adaptive_baseline_demo(db=db)

        office_cmp = compare.get("office_demo", {})
        flex_cmp = compare.get("flex_demo", {})

        print()
        print("office_demo")
        print("  Baseline Score :", office_cmp.get("baseline_score"))
        print("  Judgment       :", office_cmp.get("judgment"))
        print("  Reasons        :", office_cmp.get("reasons"))

        print()
        print("flex_demo")
        print("  Baseline Score :", flex_cmp.get("baseline_score"))
        print("  Judgment       :", flex_cmp.get("judgment"))
        print("  Reasons        :", flex_cmp.get("reasons"))

        office_score = float(office_cmp.get("baseline_score") or 0)
        flex_score = float(flex_cmp.get("baseline_score") or 0)

        print()
        print("=" * 72)

        if (
            office_score > flex_score
            and office_cmp.get("judgment") == "개인 기준선 이탈"
            and flex_cmp.get("judgment") == "개인 정상 패턴"
        ):
            print("[PASS] Adaptive 비교가 정상적으로 차이를 냅니다.")
        else:
            print("[WARN] 비교 결과가 기대 패턴과 다릅니다.")
            print("       office_demo는 이탈, flex_demo는 정상이어야 합니다.")

        print("=" * 72)
    finally:
        db.close()

if __name__ == "__main__":
    main()
