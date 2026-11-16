from pathlib import Path
import shutil
import sys
import re

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

if not APP.exists():
    print("[ERROR] App.jsx를 찾지 못했습니다.")
    print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
    sys.exit(1)

backup = APP.with_name(APP.name + ".before_soar_runtime_hotfix_v5_1")
if not backup.exists():
    shutil.copy2(APP, backup)
    print(f"[BACKUP] {backup.relative_to(ROOT)}")

app = APP.read_text(encoding="utf-8")
start = app.find("function SoarControlPage(){")
if start < 0:
    raise RuntimeError("SoarControlPage를 찾지 못했습니다.")

end_candidates = [
    app.find("\nfunction BehaviorPage", start),
    app.find("\nfunction CertPage", start),
    app.find("\nfunction UserAnalysisPage", start),
]
end_candidates = [x for x in end_candidates if x > start]
end = min(end_candidates) if end_candidates else len(app)

component = app[start:end]

# ------------------------------------------------------------
# 1) stageKo를 반드시 함수로 보장
# ------------------------------------------------------------
stage_function = """  const stageKo=v=>({
    NORMAL_ACTIVITY:'정상 활동',
    ACCESS_ATTEMPT:'접근 시도',
    ACCOUNT_ACCESS:'계정 접근',
    SENSITIVE_DATA_ACCESS:'민감정보 접근',
    DEVICE_PREPARATION:'장치 준비',
    EXFILTRATION_PREPARATION:'유출 준비'
  }[String(v||'').toUpperCase()]||v||'-')

"""

if "const stageKo=v=>" not in component:
    insert_at = component.find("  const vectorKo=v=>")
    if insert_at < 0:
        insert_at = component.find("  const operationKo=")
    if insert_at < 0:
        insert_at = component.find("\n  return <>")
    if insert_at < 0:
        raise RuntimeError("stageKo 삽입 위치를 찾지 못했습니다.")
    component = component[:insert_at] + stage_function + component[insert_at:]
    print("[PATCH] stageKo function added")
else:
    print("[OK] stageKo function already exists")

# ------------------------------------------------------------
# 2) responseLevelKo를 함수 형태로 통일
# ------------------------------------------------------------
response_object_pattern = re.compile(
    r"""  const responseLevelKo=\{\s*
    OBSERVE:'관찰',\s*
    ENHANCED_MONITORING:'강화 모니터링',\s*
    PREPARE_CONTROL:'제어 준비',\s*
    SELECTIVE_PREVENT:'선별적 차단'\s*
  \}\s*
""",
    re.X,
)

response_function = """  const responseLevelKo=v=>({
    OBSERVE:'관찰',
    ENHANCED_MONITORING:'강화 모니터링',
    PREPARE_CONTROL:'제어 준비',
    SELECTIVE_PREVENT:'선별적 차단'
  }[String(v||'').toUpperCase()]||v||'-')

"""

if response_object_pattern.search(component):
    component = response_object_pattern.sub(response_function, component, count=1)
    print("[PATCH] responseLevelKo object -> function")
elif "const responseLevelKo=v=>" in component:
    print("[OK] responseLevelKo is already a function")
elif "const responseLevelKo=" not in component:
    insert_at = component.find("  const vectorKo=v=>")
    if insert_at < 0:
        insert_at = component.find("\n  return <>")
    component = component[:insert_at] + response_function + component[insert_at:]
    print("[PATCH] responseLevelKo function added")

# ------------------------------------------------------------
# 3) GRU 카드에서 객체형 접근이 남아 있어도 함수 호출로 통일
# ------------------------------------------------------------
component = component.replace(
    "responseLevelKo[latestGruPrediction.response_level]||latestGruPrediction.response_level",
    "responseLevelKo(latestGruPrediction.response_level)"
)

# ------------------------------------------------------------
# 4) vectorKo / controlKo 존재 보장
# ------------------------------------------------------------
if "const vectorKo=v=>" not in component:
    vector_function = """  const vectorKo=v=>({
    NONE:'없음',
    ACCOUNT_COMPROMISE:'계정 탈취 가능성',
    SENSITIVE_DATA_ACCESS:'민감정보 접근',
    USB_EXFILTRATION:'USB 기반 정보 유출',
    POTENTIAL_EXFILTRATION:'정보 유출 가능성'
  }[String(v||'').toUpperCase()]||v||'-')

"""
    insert_at = component.find("\n  return <>")
    component = component[:insert_at] + vector_function + component[insert_at:]
    print("[PATCH] vectorKo function added")

if "const controlKo=v=>" not in component:
    control_function = """  const controlKo=v=>({
    USB_WRITE_RESTRICT:'USB 쓰기 제한'
  }[String(v||'').toUpperCase()]||v||'없음')

"""
    insert_at = component.find("\n  return <>")
    component = component[:insert_at] + control_function + component[insert_at:]
    print("[PATCH] controlKo function added")

app = app[:start] + component + app[end:]
APP.write_text(app, encoding="utf-8")

print("[WRITE] sentinel-react-frontend/src/App.jsx")
print()
print("=" * 78)
print("SOAR runtime hotfix v5.1 applied")
print("=" * 78)
print("- stageKo guaranteed")
print("- responseLevelKo normalized to function")
print("- vectorKo/controlKo guaranteed")
print("- GRU response-level lookup normalized")
print()
print("Next:")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
