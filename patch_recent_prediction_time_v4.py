from pathlib import Path
import shutil
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

if not APP.exists():
    print("[ERROR] sentinel-react-frontend/src/App.jsx 를 찾지 못했습니다.")
    print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
    sys.exit(1)

backup = APP.with_name(APP.name + ".before_recent_prediction_time_label_v4")
if not backup.exists():
    shutil.copy2(APP, backup)
    print(f"[BACKUP] {backup.relative_to(ROOT)}")

app = APP.read_text(encoding="utf-8")
changed = 0

replacements = [
    (
        'label="현재 위협 단계"',
        'label="최근 탐지 위협 단계"',
    ),
    (
        'label="Threat Progress"',
        'label="최근 탐지 공격 진행도"',
    ),
    (
        'label="Prediction Confidence"',
        'label="최근 탐지 신뢰도"',
    ),
    (
        'help="공격 흐름 진행도"',
        'help={latestPrediction?.created_at?`마지막 탐지 ${fmt(latestPrediction.created_at)} KST`:"저장된 Prediction 없음"}',
    ),
    (
        '<SectionHeader>최신 예측 분석</SectionHeader>',
        '<SectionHeader>최근 탐지 Prediction</SectionHeader>',
    ),
    (
        '<span>공격 진행 신뢰도</span>',
        '<span>최근 탐지 신뢰도</span>',
    ),
    (
        '<span>공격 진행도</span>',
        '<span>최근 탐지 공격 진행도</span>',
    ),
]

for old, new in replacements:
    if old in app:
        app = app.replace(old, new, 1)
        changed += 1
        print(f"[PATCH] {old} -> updated")

old_small = """<small>{latestGruPrediction?.response_level?responseLevelKo[latestGruPrediction.response_level]||latestGruPrediction.response_level:'현재 저장된 공격 진행 정보 없음'}</small>"""
new_small = """<small>{latestGruPrediction?.response_level
  ? `${responseLevelKo[latestGruPrediction.response_level]||latestGruPrediction.response_level}${latestGruPrediction?.created_at?` · ${fmt(latestGruPrediction.created_at)} KST`:''}`
  : '최근 저장된 공격 진행 정보 없음'}</small>"""
if old_small in app:
    app = app.replace(old_small, new_small, 1)
    changed += 1
    print("[PATCH] GRU card recent prediction timestamp added")

old_caption = """최근 사용자 행동의 순서와 Risk · Sequence · Personal/Peer UEBA 신호를 결합해 현재 위협 진행 단계와 다음 공격 벡터를 예측합니다."""
new_caption = """최근 사용자 행동의 순서와 Risk · Sequence · Personal/Peer UEBA 신호를 결합해 위협 진행 단계를 판단합니다. 상단 수치는 마지막으로 저장된 탐지 결과이며 현재 실시간 상태와 구분해 표시합니다."""
if old_caption in app:
    app = app.replace(old_caption, new_caption, 1)
    changed += 1
    print("[PATCH] predictive progression explanation clarified")

old_caption2 = """최근 사용자 행동과 Risk · Sequence · Personal/Peer UEBA 신호를 결합해 현재 위협 진행 단계와 다음 공격 벡터를 예측하고,"""
new_caption2 = """최근 사용자 행동과 Risk · Sequence · Personal/Peer UEBA 신호를 결합해 위협 진행 단계를 판단하며, 표시되는 Prediction 수치는 마지막으로 저장된 탐지 결과입니다."""
if old_caption2 in app:
    app = app.replace(old_caption2, new_caption2, 1)
    changed += 1
    print("[PATCH] predictive progression explanation clarified (alt)")

if changed == 0:
    print("[WARN] 자동 교체 대상 문자열을 찾지 못했습니다.")
    print("현재 App.jsx 버전이 예상과 다를 수 있습니다.")
    sys.exit(2)

APP.write_text(app, encoding="utf-8")
print("[WRITE] sentinel-react-frontend/src/App.jsx")
print()
print("=" * 78)
print("SENTINEL Recent Prediction Label v4 applied")
print("=" * 78)
print("- 95% is labeled as the most recently detected progress, not current live progress")
print("- detection timestamp is displayed with KST label where available")
print()
print("Next:")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
print()
print("Railway web service variable required:")
print("  TZ=Asia/Seoul")
print("Then redeploy the web service.")
