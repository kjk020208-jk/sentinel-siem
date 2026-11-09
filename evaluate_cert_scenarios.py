import argparse
import csv
from pathlib import Path

import pandas as pd


def norm_ver(v):
    return str(v).strip().lower().replace("r", "")


def find_insiders_csv(root: Path) -> Path:
    hits = list(root.rglob("insiders.csv"))
    if not hits:
        raise FileNotFoundError(f"insiders.csv를 찾지 못했습니다: {root}")
    return hits[0]


def resolve_detail_file(root: Path, row) -> Path | None:
    details = str(row.get("details", "")).strip()
    scenario = str(row.get("scenario", "")).strip()
    dataset = norm_ver(row.get("dataset", ""))

    if not details or details.lower() == "nan":
        return None

    candidates = [
        root / details,
        root / f"r{dataset}-{scenario}" / details,
        root / f"{dataset}-{scenario}" / details,
    ]

    for p in candidates:
        if p.exists():
            return p

    hits = list(root.rglob(Path(details).name))
    return hits[0] if hits else None


def load_scenarios(answers_root: Path, dataset="4.2"):
    insiders_path = find_insiders_csv(answers_root)
    insiders = pd.read_csv(insiders_path)

    insiders = insiders[
        insiders["dataset"].astype(str).map(norm_ver) == norm_ver(dataset)
    ].copy()

    scenarios = []

    for idx, row in insiders.iterrows():
        detail_file = resolve_detail_file(insiders_path.parent, row)
        if detail_file is None:
            detail_file = resolve_detail_file(answers_root, row)

        event_ids = set()

        if detail_file and detail_file.exists():
            with detail_file.open(
                "r",
                encoding="utf-8",
                errors="ignore",
                newline=""
            ) as f:
                reader = csv.reader(f)
                for fields in reader:
                    if len(fields) < 2:
                        continue
                    event_id = fields[1].strip().strip('"')
                    if event_id and event_id.lower() not in {"id", "event_id"}:
                        event_ids.add(event_id)

        scenarios.append(
            {
                "scenario_row": idx + 1,
                "scenario": str(row.get("scenario", "")),
                "user": str(row.get("user", "")),
                "details": str(row.get("details", "")),
                "event_ids": event_ids,
            }
        )

    return insiders_path, scenarios


def load_event_scores(path: Path):
    df = pd.read_csv(path, encoding="utf-8-sig", low_memory=False)

    required = {"raw_event_id", "risk_score"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"평가 상세 CSV에 필요한 컬럼이 없습니다: {sorted(missing)}")

    df["raw_event_id"] = df["raw_event_id"].astype(str).str.strip()
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0.0)

    # raw_event_id 중복 시 가장 높은 점수
    scores = (
        df.groupby("raw_event_id", as_index=False)
        .agg(risk_score=("risk_score", "max"))
    )

    return dict(zip(scores["raw_event_id"], scores["risk_score"]))


def main():
    ap = argparse.ArgumentParser(description="CERT r4.2 시나리오 단위 탐지 평가")
    ap.add_argument(
        "--answers",
        default="data/cert_r4.2/answers",
    )
    ap.add_argument(
        "--details",
        default="data/cert_r4.2/evaluation_event_details.csv",
        help="cert_evaluate.py가 만든 이벤트별 평가 상세 CSV",
    )
    ap.add_argument(
        "--dataset",
        default="4.2",
    )
    ap.add_argument(
        "--threshold",
        type=float,
        default=30.0,
    )
    ap.add_argument(
        "--output",
        default="data/cert_r4.2/scenario_evaluation.csv",
    )
    args = ap.parse_args()

    print("[1/3] CERT 시나리오 로딩...")
    insiders_path, scenarios = load_scenarios(
        Path(args.answers),
        args.dataset
    )
    print(f"  - insiders.csv: {insiders_path}")
    print(f"  - 시나리오 수: {len(scenarios)}개")

    print("[2/3] SENTINEL 이벤트 점수 로딩...")
    score_map = load_event_scores(Path(args.details))
    print(f"  - 평가 이벤트 점수: {len(score_map):,}개")

    rows = []

    for s in scenarios:
        ids = s["event_ids"]

        in_sample = [eid for eid in ids if eid in score_map]
        detected = [
            eid for eid in in_sample
            if score_map[eid] >= args.threshold
        ]

        max_score = (
            max((score_map[eid] for eid in in_sample), default=0.0)
        )

        rows.append(
            {
                "scenario_row": s["scenario_row"],
                "scenario": s["scenario"],
                "user": s["user"],
                "details": s["details"],
                "ground_truth_event_count": len(ids),
                "events_in_current_sample": len(in_sample),
                "detected_events": len(detected),
                "scenario_detected": int(len(detected) > 0),
                "max_risk_score": round(float(max_score), 2),
            }
        )

    out_df = pd.DataFrame(rows)

    evaluable = out_df[out_df["events_in_current_sample"] > 0].copy()
    detected_count = int(evaluable["scenario_detected"].sum())
    evaluable_count = len(evaluable)

    print("[3/3] 시나리오 단위 평가")
    print()
    print("=" * 72)
    print(f"Risk threshold >= {args.threshold:g}")
    print(f"전체 CERT r{args.dataset} 시나리오: {len(out_df)}개")
    print(f"현재 10만 건에 일부라도 포함된 시나리오: {evaluable_count}개")
    print(f"탐지된 시나리오: {detected_count}개")
    print(
        "시나리오 탐지율: "
        + (
            f"{detected_count / evaluable_count * 100:.2f}%"
            if evaluable_count
            else "N/A"
        )
    )
    print("=" * 72)

    print("\n[미탐 시나리오]")
    missed = evaluable[evaluable["scenario_detected"] == 0]
    if missed.empty:
        print("없음")
    else:
        print(
            missed[
                [
                    "scenario_row",
                    "scenario",
                    "user",
                    "events_in_current_sample",
                    "max_risk_score",
                ]
            ].to_string(index=False)
        )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(out_path, index=False, encoding="utf-8-sig")

    print()
    print(f"[완료] {out_path}")


if __name__ == "__main__":
    main()
