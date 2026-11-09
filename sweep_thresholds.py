import argparse
import csv
from pathlib import Path
import pandas as pd


def norm_ver(v):
    return str(v).strip().lower().replace("r", "")


def find_insiders_csv(root: Path):
    hits = list(root.rglob("insiders.csv"))
    if not hits:
        raise FileNotFoundError(f"insiders.csv not found: {root}")
    return hits[0]


def resolve_detail_file(root: Path, row):
    details = str(row.get("details", "")).strip()
    scenario = str(row.get("scenario", "")).strip()
    dataset = norm_ver(row.get("dataset", ""))

    if not details or details.lower() == "nan":
        return None

    for p in [
        root / details,
        root / f"r{dataset}-{scenario}" / details,
        root / f"{dataset}-{scenario}" / details,
    ]:
        if p.exists():
            return p

    hits = list(root.rglob(Path(details).name))
    return hits[0] if hits else None


def load_scenarios(root: Path, dataset="4.2"):
    insiders_path = find_insiders_csv(root)
    insiders = pd.read_csv(insiders_path)

    insiders = insiders[
        insiders["dataset"].astype(str).map(norm_ver)
        == norm_ver(dataset)
    ].copy()

    out = []

    for _, row in insiders.iterrows():
        p = (
            resolve_detail_file(insiders_path.parent, row)
            or resolve_detail_file(root, row)
        )

        ids = set()

        if p and p.exists():
            with p.open(
                "r",
                encoding="utf-8",
                errors="ignore",
                newline=""
            ) as f:
                for fields in csv.reader(f):
                    if len(fields) >= 2:
                        eid = fields[1].strip().strip('"')

                        if eid and eid.lower() not in {
                            "id",
                            "event_id"
                        }:
                            ids.add(eid)

        out.append(ids)

    return out


def safe_div(a, b):
    return a / b if b else 0.0


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "--details",
        default="data/cert_r4.2/evaluation_event_details.csv"
    )

    ap.add_argument(
        "--answers",
        default="data/cert_r4.2/answers"
    )

    ap.add_argument(
        "--dataset",
        default="4.2"
    )

    ap.add_argument(
        "--start",
        type=float,
        default=20.0
    )

    ap.add_argument(
        "--end",
        type=float,
        default=30.0
    )

    ap.add_argument(
        "--step",
        type=float,
        default=0.5
    )

    ap.add_argument(
        "--output",
        default="data/cert_r4.2/threshold_sweep.csv"
    )

    args = ap.parse_args()

    df = pd.read_csv(
        args.details,
        encoding="utf-8-sig",
        low_memory=False
    )

    df["raw_event_id"] = (
        df["raw_event_id"]
        .astype(str)
        .str.strip()
    )

    df["risk_score"] = pd.to_numeric(
        df["risk_score"],
        errors="coerce"
    ).fillna(0.0)

    df["is_malicious"] = (
        df["is_malicious"]
        .astype(str)
        .str.lower()
        .isin(["true", "1", "yes"])
    )

    score_map = dict(
        zip(
            df["raw_event_id"],
            df["risk_score"]
        )
    )

    scenarios = load_scenarios(
        Path(args.answers),
        args.dataset
    )

    rows = []

    t = args.start

    while t <= args.end + 1e-9:
        pred = df["risk_score"] >= t
        truth = df["is_malicious"]

        tp = int((truth & pred).sum())
        fp = int((~truth & pred).sum())
        tn = int((~truth & ~pred).sum())
        fn = int((truth & ~pred).sum())

        precision = safe_div(
            tp,
            tp + fp
        )

        recall = safe_div(
            tp,
            tp + fn
        )

        fpr = safe_div(
            fp,
            fp + tn
        )

        f1 = (
            safe_div(
                2 * precision * recall,
                precision + recall
            )
            if precision + recall
            else 0.0
        )

        evaluable = 0
        scenario_detected = 0

        for ids in scenarios:
            present = [
                eid
                for eid in ids
                if eid in score_map
            ]

            if not present:
                continue

            evaluable += 1

            if any(
                score_map[eid] >= t
                for eid in present
            ):
                scenario_detected += 1

        scenario_rate = safe_div(
            scenario_detected,
            evaluable
        )

        combined = (
            scenario_rate * 0.55
            + (1 - fpr) * 0.25
            + recall * 0.20
        )

        rows.append(
            {
                "threshold": round(t, 2),
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "precision_pct": round(
                    precision * 100,
                    2
                ),
                "recall_pct": round(
                    recall * 100,
                    2
                ),
                "fpr_pct": round(
                    fpr * 100,
                    2
                ),
                "f1_pct": round(
                    f1 * 100,
                    2
                ),
                "scenario_detected":
                    scenario_detected,
                "scenario_total":
                    evaluable,
                "scenario_detection_pct":
                    round(
                        scenario_rate * 100,
                        2
                    ),
                "combined_score":
                    round(
                        combined,
                        4
                    ),
            }
        )

        t += args.step

    out = pd.DataFrame(rows)

    out.to_csv(
        args.output,
        index=False,
        encoding="utf-8-sig"
    )

    print("\n[임계값 탐색 결과]")
    print(
        out.to_string(
            index=False
        )
    )

    print("\n[추천 상위 5개]")

    print(
        out.sort_values(
            [
                "combined_score",
                "scenario_detection_pct",
                "fpr_pct"
            ],
            ascending=[
                False,
                False,
                True
            ]
        )
        .head(5)
        .to_string(
            index=False
        )
    )

    print(
        f"\n[저장] {args.output}"
    )


if __name__ == "__main__":
    main()