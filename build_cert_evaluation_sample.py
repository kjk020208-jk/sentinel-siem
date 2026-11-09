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


def load_malicious_ids(answers_root: Path, dataset="4.2"):
    insiders_path = find_insiders_csv(answers_root)
    insiders = pd.read_csv(insiders_path)

    insiders = insiders[
        insiders["dataset"].astype(str).map(norm_ver) == norm_ver(dataset)
    ].copy()

    mal_ids = set()
    for _, row in insiders.iterrows():
        p = resolve_detail_file(insiders_path.parent, row)
        if p is None:
            p = resolve_detail_file(answers_root, row)
        if p is None or not p.exists():
            continue

        with p.open("r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.reader(f)
            for fields in reader:
                if len(fields) < 2:
                    continue
                event_id = fields[1].strip().strip('"')
                if event_id and event_id.lower() not in {"id", "event_id"}:
                    mal_ids.add(event_id)

    return mal_ids


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="data/cert_r4.2/normalized_events.csv")
    parser.add_argument("--answers", default="data/cert_r4.2/answers")
    parser.add_argument("--dataset", default="4.2")
    parser.add_argument("--size", type=int, default=100000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--output",
        default="data/cert_r4.2/evaluation_sample_100k.csv",
    )
    args = parser.parse_args()

    source = Path(args.source)
    answers = Path(args.answers)
    output = Path(args.output)

    print("[1/4] 악성 이벤트 ID 로딩...")
    mal_ids = load_malicious_ids(answers, args.dataset)
    print(f"  - 전체 악성 이벤트 ID: {len(mal_ids):,}개")

    print("[2/4] 정규화 이벤트 로딩...")
    df = pd.read_csv(source, low_memory=False)
    if "raw_event_id" not in df.columns:
        raise ValueError("source CSV에 raw_event_id 컬럼이 없습니다.")

    df["raw_event_id"] = df["raw_event_id"].astype(str).str.strip()

    malicious = df[df["raw_event_id"].isin(mal_ids)].copy()
    normal = df[~df["raw_event_id"].isin(mal_ids)].copy()

    print(f"  - source 내 악성 이벤트: {len(malicious):,}건")
    print(f"  - source 내 정상 이벤트: {len(normal):,}건")

    if len(malicious) == 0:
        raise ValueError(
            "현재 normalized_events.csv 자체에 악성 이벤트가 없습니다.\n"
            "전체 CERT 데이터에서 normalized_events.csv를 다시 만들어야 합니다."
        )

    if len(malicious) >= args.size:
        sample = malicious.sample(n=args.size, random_state=args.seed)
    else:
        normal_needed = args.size - len(malicious)
        if normal_needed > len(normal):
            normal_needed = len(normal)

        normal_sample = normal.sample(
            n=normal_needed,
            random_state=args.seed,
        )
        sample = pd.concat([malicious, normal_sample], ignore_index=True)

    # 실제 시퀀스 분석을 위해 시간순 정렬
    if "timestamp" in sample.columns:
        sample["timestamp"] = pd.to_datetime(sample["timestamp"], errors="coerce")
        sample = sample.sort_values("timestamp", kind="mergesort")

    sample["is_malicious_ground_truth"] = (
        sample["raw_event_id"].isin(mal_ids)
    ).astype(int)

    output.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(output, index=False, encoding="utf-8-sig")

    print("[3/4] 평가 세트 생성 완료")
    print(f"  - 총 이벤트: {len(sample):,}건")
    print(f"  - 악성 이벤트: {int(sample['is_malicious_ground_truth'].sum()):,}건")
    print(f"  - 정상 이벤트: {len(sample) - int(sample['is_malicious_ground_truth'].sum()):,}건")

    print("[4/4] 저장 완료")
    print(f"  - {output}")


if __name__ == "__main__":
    main()
