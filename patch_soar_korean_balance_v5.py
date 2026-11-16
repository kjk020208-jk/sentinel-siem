
from pathlib import Path
import shutil
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
CSS = ROOT / "sentinel-react-frontend" / "src" / "styles.css"

for p in (APP, CSS):
    if not p.exists():
        print(f"[ERROR] missing: {p}")
        sys.exit(1)

for p in (APP, CSS):
    b = p.with_name(p.name + ".before_soar_korean_balance_v5")
    if not b.exists():
        shutil.copy2(p, b)
        print(f"[BACKUP] {b.relative_to(ROOT)}")

app = APP.read_text(encoding="utf-8")

# 1) Section title / captions
pairs = [
    ("<SectionHeader>Predictive Threat Progression</SectionHeader>",
     "<SectionHeader>공격 진행 단계 분석</SectionHeader>"),
    ("<SectionHeader>Prediction 제어 판단</SectionHeader>",
     "<SectionHeader>예측 기반 제어 판단</SectionHeader>"),
    ("<SectionHeader>Prediction 이력</SectionHeader>",
     "<SectionHeader>공격 진행 예측 이력</SectionHeader>"),
    ("SOAR / Prediction API 오류", "SOAR / 예측 API 오류"),
]
for old, new in pairs:
    if old in app:
        app = app.replace(old, new)
        print(f"[PATCH] text updated: {old}")

# 2) Korean helper functions
soar_start = app.find("function SoarControlPage(){")
if soar_start < 0:
    raise RuntimeError("SoarControlPage not found")

if "const vectorKo=v=>" not in app[soar_start:]:
    insert_at = app.find("\n  return <>", soar_start)
    if insert_at < 0:
        raise RuntimeError("SOAR helper insertion point not found")

    helpers = '''
  const vectorKo=v=>({
    NONE:'없음',
    ACCOUNT_COMPROMISE:'계정 탈취 가능성',
    SENSITIVE_DATA_ACCESS:'민감정보 접근',
    USB_EXFILTRATION:'USB 기반 정보 유출',
    POTENTIAL_EXFILTRATION:'정보 유출 가능성'
  }[String(v||'').toUpperCase()]||v||'-')

  const controlKo=v=>({
    USB_WRITE_RESTRICT:'USB 쓰기 제한'
  }[String(v||'').toUpperCase()]||v||'없음')
'''
    app = app[:insert_at] + helpers + app[insert_at:]
    print("[PATCH] vector/control Korean helpers added")

# 3) Metric labels
replacements = [
    ('label="현재 위협 단계"', 'label="최근 탐지 위협 단계"'),
    ('label="Threat Progress"', 'label="최근 탐지 공격 진행도"'),
    ('label="Prediction Confidence"', 'label="최근 탐지 신뢰도"'),
    ('label="자동 Micro-Control"', 'label="자동 선제 제어"'),
    ('help="공격 흐름 진행도"', 'help="마지막 저장된 공격 진행 판단"'),
]
for old, new in replacements:
    if old in app:
        app = app.replace(old, new)

# raw stage -> Korean
app = app.replace(
    "value={latestPrediction?.current_stage||'-'}",
    "value={latestPrediction?stageKo(latestPrediction.current_stage):'-'}"
)

# raw vector help -> Korean
app = app.replace(
    "help={latestPrediction?.predicted_vector||'다음 공격 벡터'}",
    "help={latestPrediction?vectorKo(latestPrediction.predicted_vector):'예측 벡터 없음'}"
)

# 4) Detail/table Koreanization
app = app.replace(
    "value={latestPrediction.predicted_vector||'-'}",
    "value={vectorKo(latestPrediction.predicted_vector)}"
)
app = app.replace(
    "value={latestPrediction.recommended_control||'없음'}",
    "value={controlKo(latestPrediction.recommended_control)}"
)

for old, new in [
    ("p.current_stage||'-'", "stageKo(p.current_stage)"),
    ("p.predicted_vector||'-'", "vectorKo(p.predicted_vector)"),
    ("p.recommended_control||'-'", "controlKo(p.recommended_control)"),
    ("p.response_level||'-'", "responseLevelKo(p.response_level)"),
]:
    app = app.replace(old, new)

for old, new in [
    ("'현재 단계'", "'탐지 단계'"),
    ("'예측 벡터'", "'예상 공격 경로'"),
    ("'다음 벡터'", "'예상 공격 경로'"),
    ("'추천 제어'", "'권장 제어'"),
    ("'대응 단계'", "'대응 수준'"),
]:
    app = app.replace(old, new)

APP.write_text(app, encoding="utf-8")
print("[WRITE] sentinel-react-frontend/src/App.jsx")

# 5) CSS
css = CSS.read_text(encoding="utf-8")
marker = "/* ===== SENTINEL UI BALANCE + OVERFLOW GUARD V5 ===== */"

if marker not in css:
    css_patch = r'''

/* ===== SENTINEL UI BALANCE + OVERFLOW GUARD V5 ===== */
.st-metric-grid{align-items:stretch}
.st-metric{
  box-sizing:border-box;
  min-width:0;
  min-height:104px;
  padding:12px 14px;
  border:1px solid rgba(255,255,255,.055);
  border-radius:9px;
  background:rgba(255,255,255,.018);
  overflow:hidden;
}
.st-metric-label{
  min-height:18px;
  margin-bottom:7px;
  font-size:10px;
  line-height:1.35;
  font-weight:650;
  letter-spacing:-.01em;
  white-space:normal;
  overflow-wrap:anywhere;
}
.st-metric-value{
  display:block;
  width:100%;
  max-width:100%;
  font-size:clamp(19px,2vw,28px);
  line-height:1.12;
  letter-spacing:-.035em;
  white-space:normal;
  overflow-wrap:anywhere;
  word-break:keep-all;
}
.st-metric-help{
  margin-top:7px;
  min-height:14px;
  font-size:9px;
  line-height:1.45;
  white-space:normal;
  overflow-wrap:anywhere;
  word-break:keep-all;
}

.detail-grid,.related-detail-grid{align-items:stretch}
.detail-box{min-width:0;overflow:hidden}
.detail-label{line-height:1.35;white-space:normal}
.detail-value{
  max-width:100%;
  font-size:12px;
  line-height:1.5;
  word-break:keep-all;
  overflow-wrap:anywhere;
}

.gru-next-action-panel,
.gru-next-action-head,
.gru-next-metrics,
.gru-next-metric,
.gru-top3-row{min-width:0}

.gru-next-title{
  max-width:100%;
  font-size:clamp(18px,2.1vw,28px);
  line-height:1.2;
  word-break:keep-all;
  overflow-wrap:anywhere;
}
.gru-next-sub,
.gru-next-note,
.gru-endpoint-toolbar strong{
  word-break:keep-all;
  overflow-wrap:anywhere;
}
.gru-next-metric{min-width:0;overflow:hidden}
.gru-next-metric span,
.gru-next-metric small{
  white-space:normal;
  word-break:keep-all;
  overflow-wrap:anywhere;
}
.gru-next-metric strong{
  max-width:100%;
  font-size:clamp(17px,1.8vw,24px);
  overflow-wrap:anywhere;
}

.table-wrap{
  width:100%;
  max-width:100%;
  overflow-x:auto;
  overflow-y:auto;
  scrollbar-gutter:stable;
}
.table-wrap table{
  width:100%;
  min-width:820px;
  table-layout:auto;
}
.table-wrap th,
.table-wrap td{
  max-width:260px;
  line-height:1.45;
  vertical-align:middle;
  white-space:normal;
  word-break:keep-all;
  overflow-wrap:anywhere;
}
.table-wrap th{font-size:9px}
.table-wrap td{font-size:10px}

.table-wrap .alert-actions{
  display:flex;
  flex-wrap:nowrap;
  gap:6px;
  min-width:max-content;
}
.table-wrap .btn{white-space:nowrap}

.section-caption,
.notice,
.evidence-item{
  max-width:100%;
  word-break:keep-all;
  overflow-wrap:anywhere;
}

@media(max-width:1200px){
  .st-metric-grid.cols4{
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}
@media(max-width:680px){
  .st-metric-grid.cols4,
  .st-metric-grid.cols3,
  .detail-grid,
  .related-detail-grid{
    grid-template-columns:1fr;
  }
  .st-metric{min-height:92px}
  .table-wrap table{min-width:720px}
}
'''
    CSS.write_text(css + css_patch, encoding="utf-8")
    print("[PATCH] UI balance/overflow CSS added")
else:
    print("[SKIP] UI balance CSS already present")

print()
print("=" * 82)
print("SENTINEL SOAR Korean + UI Balance v5 applied")
print("=" * 82)
print("- Predictive Threat Progression -> 공격 진행 단계 분석")
print("- stage/vector/control labels Koreanized")
print("- metric cards balanced")
print("- long labels/values wrap safely")
print("- tables scroll horizontally instead of breaking layout")
print("- GRU panel text overflow guarded")
print()
print("Next:")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
