import argparse
import csv
import math
import sqlite3
from pathlib import Path
import pandas as pd


def find_insiders_csv(root: Path) -> Path:
    hits = list(root.rglob('insiders.csv'))
    if not hits:
        raise FileNotFoundError(f'insiders.csv를 찾지 못했습니다: {root}')
    return hits[0]


def norm_ver(v):
    return str(v).strip().lower().replace('r', '')


def resolve_detail(root: Path, row):
    details = str(row.get('details', '')).strip()
    scenario = str(row.get('scenario', '')).strip()
    dataset = norm_ver(row.get('dataset', ''))
    if not details or details.lower() == 'nan':
        return None
    candidates = [
        root / details,
        root / f'r{dataset}-{scenario}' / details,
        root / f'{dataset}-{scenario}' / details,
    ]
    for p in candidates:
        if p.exists():
            return p
    hits = list(root.rglob(Path(details).name))
    return hits[0] if hits else None


def load_malicious_ids(answers_root: Path, dataset='4.2'):
    insiders_path = find_insiders_csv(answers_root)
    insiders = pd.read_csv(insiders_path)
    insiders = insiders[insiders['dataset'].astype(str).map(norm_ver) == norm_ver(dataset)].copy()
    malicious_ids = set()
    parsed = 0
    missing = []
    for _, row in insiders.iterrows():
        detail = resolve_detail(insiders_path.parent, row) or resolve_detail(answers_root, row)
        if detail is None:
            missing.append(str(row.get('details', '')))
            continue
        parsed += 1
        with detail.open('r', encoding='utf-8', errors='ignore', newline='') as f:
            for fields in csv.reader(f):
                if len(fields) < 2:
                    continue
                event_id = fields[1].strip().strip('"')
                if event_id and event_id.lower() not in {'id', 'event_id'}:
                    malicious_ids.add(event_id)
    return insiders_path, insiders, malicious_ids, parsed, missing


def load_predictions(db_path: Path, ids: set[str]):
    conn = sqlite3.connect(db_path)
    try:
        cols = [r[1] for r in conn.execute('PRAGMA table_info(security_events)').fetchall()]
        need = {'raw_event_id', 'risk_score', 'risk_level'}
        missing = need - set(cols)
        if missing:
            raise ValueError(f'DB에 필요한 컬럼이 없습니다: {sorted(missing)}')
        q = 'SELECT raw_event_id, risk_score, risk_level FROM security_events WHERE raw_event_id IS NOT NULL'
        df = pd.read_sql_query(q, conn)
    finally:
        conn.close()
    df['raw_event_id'] = df['raw_event_id'].astype(str).str.strip()
    df = df[df['raw_event_id'].isin(ids)].copy()
    df['risk_score'] = pd.to_numeric(df['risk_score'], errors='coerce').fillna(0.0)
    return df.groupby('raw_event_id', as_index=False).agg(risk_score=('risk_score','max'), risk_level=('risk_level','last'))


def safe(a,b):
    return a/b if b else float('nan')


def pct(v):
    return 'N/A' if math.isnan(v) else f'{v*100:.2f}%'


def evaluate(df, t):
    y = df['is_malicious'].astype(bool)
    p = df['risk_score'] >= t
    tp = int((y & p).sum()); tn = int((~y & ~p).sum())
    fp = int((~y & p).sum()); fn = int((y & ~p).sum())
    precision = safe(tp, tp+fp); recall = safe(tp, tp+fn); fpr = safe(fp, fp+tn)
    accuracy = safe(tp+tn, len(df))
    f1 = float('nan') if math.isnan(precision) or math.isnan(recall) or precision+recall == 0 else 2*precision*recall/(precision+recall)
    return dict(threshold=t,tp=tp,tn=tn,fp=fp,fn=fn,precision=precision,recall=recall,fpr=fpr,accuracy=accuracy,f1=f1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--normalized', default='data/cert_r4.2/normalized_events.csv')
    ap.add_argument('--db', default='data/security.db')
    ap.add_argument('--answers', default='data/cert_r4.2/answers')
    ap.add_argument('--dataset', default='4.2')
    ap.add_argument('--threshold', type=float, default=60.0)
    ap.add_argument('--output', default='data/cert_r4.2/evaluation_results.csv')
    a = ap.parse_args()

    print('[1/4] normalized events 로딩...')
    events = pd.read_csv(a.normalized, low_memory=False)
    required = {'raw_event_id','timestamp','user','event_type'}
    miss = required - set(events.columns)
    if miss:
        raise ValueError(f'normalized_events.csv에 필요한 컬럼이 없습니다: {sorted(miss)}')
    events['raw_event_id'] = events['raw_event_id'].astype(str).str.strip()
    ids = set(events['raw_event_id'])
    print(f'  - 평가 대상 이벤트: {len(events):,}건')

    print('[2/4] CERT ground truth 로딩...')
    insiders_path, insiders, mal_ids, parsed, missing = load_malicious_ids(Path(a.answers), a.dataset)
    overlap = ids & mal_ids
    print(f'  - insiders.csv: {insiders_path}')
    print(f'  - r{a.dataset} 시나리오 행: {len(insiders):,}개')
    print(f'  - 읽은 상세 정답 파일: {parsed:,}개')
    print(f'  - 전체 악성 이벤트 ID: {len(mal_ids):,}개')
    print(f'  - 현재 10만 건과 겹치는 악성 이벤트: {len(overlap):,}건')
    if missing:
        print(f'  - 찾지 못한 상세 파일: {len(missing):,}개')

    print('[3/4] SENTINEL 위험점수 로딩...')
    pred = load_predictions(Path(a.db), ids)
    print(f'  - DB와 매칭된 고유 이벤트: {len(pred):,}건')

    merged = events[['raw_event_id','timestamp','user','event_type']].merge(pred, on='raw_event_id', how='left')
    merged['risk_score'] = merged['risk_score'].fillna(0.0)
    merged['is_malicious'] = merged['raw_event_id'].isin(mal_ids)

    print('[4/4] 성능 평가...')
    if int(merged['is_malicious'].sum()) == 0:
        print('\n[중요] 현재 샘플에 CERT 악성 이벤트가 0건입니다.')
        print('이 경우 탐지율은 계산할 수 없고, 오탐률만 의미가 있습니다.')
        print('최종 검증용으로는 악성 이벤트가 포함된 샘플을 다시 만들어야 합니다.\n')

    thresholds = sorted(set([30.0, 60.0, 80.0, float(a.threshold)]))
    results = []
    for t in thresholds:
        r = evaluate(merged, t); results.append(r)
        print(f'\n--- Risk threshold >= {t:g} ---')
        print(f"TP: {r['tp']:,} | FP: {r['fp']:,} | TN: {r['tn']:,} | FN: {r['fn']:,}")
        print(f"Precision: {pct(r['precision'])}")
        print(f"탐지율(Recall/TPR): {pct(r['recall'])}")
        print(f"오탐률(FPR): {pct(r['fpr'])}")
        print(f"Accuracy: {pct(r['accuracy'])}")
        print(f"F1-score: {pct(r['f1'])}")

    out = Path(a.output); out.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(results).to_csv(out, index=False, encoding='utf-8-sig')
    merged.to_csv(out.with_name('evaluation_event_details.csv'), index=False, encoding='utf-8-sig')
    print(f'\n[완료] 평가 요약: {out}')

if __name__ == '__main__':
    main()
