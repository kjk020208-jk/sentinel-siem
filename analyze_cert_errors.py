import argparse
from pathlib import Path

import pandas as pd


def pct(n, d):
    return 0.0 if d == 0 else (n / d) * 100.0


def main():
    ap = argparse.ArgumentParser(description="SENTINEL CERT FN/FP 원인 분석")
    ap.add_argument(
        "--input",
        default="data/cert_r4.2/evaluation_event_details.csv",
        help="cert_evaluate.py가 생성한 이벤트별 평가 결과 CSV",
    )
    ap.add_argument(
        "--threshold",
        type=float,
        default=30.0,
        help="탐지 판정 risk_score 기준값 (기본 30)",
    )
    ap.add_argument(
        "--output-dir",
        default="data/cert_r4.2/analysis",
        help="분석 결과 저장 폴더",
    )
    args = ap.parse_args()

    src = Path(args.input)
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(src, encoding="utf-8-sig", low_memory=False)

    required = {"raw_event_id", "user", "event_type", "risk_score", "is_malicious"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"필수 컬럼이 없습니다: {sorted(missing)}")

    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0.0)
    df["is_malicious"] = (
        df["is_malicious"]
        .astype(str)
        .str.strip()
        .str.lower()
        .isin(["true", "1", "yes"])
    )
    df["predicted"] = df["risk_score"] >= args.threshold

    df["result_type"] = "TN"
    df.loc[df["is_malicious"] & df["predicted"], "result_type"] = "TP"
    df.loc[df["is_malicious"] & ~df["predicted"], "result_type"] = "FN"
    df.loc[~df["is_malicious"] & df["predicted"], "result_type"] = "FP"

    tp = df[df["result_type"] == "TP"]
    fn = df[df["result_type"] == "FN"]
    fp = df[df["result_type"] == "FP"]
    tn = df[df["result_type"] == "TN"]

    print("=" * 72)
    print(f"SENTINEL CERT 오류 분석 | threshold >= {args.threshold:g}")
    print("=" * 72)
    print(f"전체: {len(df):,}")
    print(f"TP: {len(tp):,} | FN: {len(fn):,} | FP: {len(fp):,} | TN: {len(tn):,}")
    print(f"탐지율: {pct(len(tp), len(tp)+len(fn)):.2f}%")
    print(f"오탐률: {pct(len(fp), len(fp)+len(tn)):.2f}%")

    # 1) 악성 이벤트 종류별 탐지/미탐
    mal = df[df["is_malicious"]].copy()
    by_event = (
        mal.groupby("event_type")
        .agg(
            malicious_count=("raw_event_id", "count"),
            detected=("predicted", "sum"),
            avg_score=("risk_score", "mean"),
            median_score=("risk_score", "median"),
            max_score=("risk_score", "max"),
        )
        .reset_index()
    )
    by_event["missed"] = by_event["malicious_count"] - by_event["detected"]
    by_event["detection_rate_pct"] = (
        by_event["detected"] / by_event["malicious_count"] * 100
    ).round(2)
    by_event = by_event.sort_values(
        ["missed", "malicious_count"], ascending=[False, False]
    )

    print("\n[1] 악성 이벤트 종류별 탐지 현황")
    print(by_event.to_string(index=False))

    # 2) FN 종류별
    fn_event = (
        fn.groupby("event_type")
        .agg(
            fn_count=("raw_event_id", "count"),
            avg_score=("risk_score", "mean"),
            median_score=("risk_score", "median"),
            max_score=("risk_score", "max"),
        )
        .reset_index()
        .sort_values("fn_count", ascending=False)
    )

    print("\n[2] FN(미탐) 이벤트 종류")
    if len(fn_event):
        print(fn_event.to_string(index=False))
    else:
        print("FN 없음")

    # 3) FP 종류별
    fp_event = (
        fp.groupby("event_type")
        .agg(
            fp_count=("raw_event_id", "count"),
            avg_score=("risk_score", "mean"),
            median_score=("risk_score", "median"),
            max_score=("risk_score", "max"),
        )
        .reset_index()
        .sort_values("fp_count", ascending=False)
    )

    print("\n[3] FP(오탐) 이벤트 종류")
    if len(fp_event):
        print(fp_event.to_string(index=False))
    else:
        print("FP 없음")

    # 4) 점수 구간
    bins = [-0.001, 9.999, 19.999, 29.999, 39.999, 49.999, 59.999, 79.999, 1000]
    labels = ["0-9", "10-19", "20-29", "30-39", "40-49", "50-59", "60-79", "80+"]
    df["score_band"] = pd.cut(df["risk_score"], bins=bins, labels=labels)

    score_dist = (
        df.groupby(["score_band", "is_malicious"], observed=True)
        .size()
        .unstack(fill_value=0)
        .rename(columns={False: "normal", True: "malicious"})
        .reset_index()
    )
    for col in ["normal", "malicious"]:
        if col not in score_dist.columns:
            score_dist[col] = 0

    print("\n[4] 위험점수 구간별 정상/악성 분포")
    print(score_dist.to_string(index=False))

    # 5) FN이 많은 사용자
    fn_user = (
        fn.groupby("user")
        .agg(
            fn_count=("raw_event_id", "count"),
            avg_score=("risk_score", "mean"),
        )
        .reset_index()
        .sort_values("fn_count", ascending=False)
        .head(20)
    )

    print("\n[5] FN이 많은 사용자 TOP 20")
    if len(fn_user):
        print(fn_user.to_string(index=False))
    else:
        print("FN 없음")

    # 6) FP가 많은 사용자
    fp_user = (
        fp.groupby("user")
        .agg(
            fp_count=("raw_event_id", "count"),
            avg_score=("risk_score", "mean"),
        )
        .reset_index()
        .sort_values("fp_count", ascending=False)
        .head(20)
    )

    print("\n[6] FP가 많은 사용자 TOP 20")
    if len(fp_user):
        print(fp_user.to_string(index=False))
    else:
        print("FP 없음")

    # 7) raw detail save
    by_event.to_csv(outdir / "malicious_by_event_type.csv", index=False, encoding="utf-8-sig")
    fn_event.to_csv(outdir / "fn_by_event_type.csv", index=False, encoding="utf-8-sig")
    fp_event.to_csv(outdir / "fp_by_event_type.csv", index=False, encoding="utf-8-sig")
    score_dist.to_csv(outdir / "score_distribution.csv", index=False, encoding="utf-8-sig")
    fn_user.to_csv(outdir / "fn_users_top20.csv", index=False, encoding="utf-8-sig")
    fp_user.to_csv(outdir / "fp_users_top20.csv", index=False, encoding="utf-8-sig")
    fn.to_csv(outdir / "false_negatives.csv", index=False, encoding="utf-8-sig")
    fp.to_csv(outdir / "false_positives.csv", index=False, encoding="utf-8-sig")

    print("\n[완료]")
    print(f"분석 결과 저장 폴더: {outdir}")
    print("특히 아래 출력 3개를 보내주면 다음 규칙 수정 가능:")
    print("  1) [1] 악성 이벤트 종류별 탐지 현황")
    print("  2) [2] FN(미탐) 이벤트 종류")
    print("  3) [3] FP(오탐) 이벤트 종류")


if __name__ == "__main__":
    main()
