from pathlib import Path
import shutil
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

candidates = [
    APP.with_name(APP.name + ".before_soar_korean_balance_v5"),
    APP.with_name(APP.name + ".before_soar_runtime_hotfix_v5_1"),
]

if not APP.exists():
    print("[ERROR] 현재 App.jsx를 찾지 못했습니다.")
    print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
    sys.exit(1)

source = None
for p in candidates:
    if p.exists():
        source = p
        break

if source is None:
    print("[ERROR] 복구용 백업 파일을 찾지 못했습니다.")
    for p in candidates:
        print(" -", p)
    sys.exit(2)

safety = APP.with_name(APP.name + ".broken_soar_before_rollback")
if not safety.exists():
    shutil.copy2(APP, safety)
    print(f"[BACKUP CURRENT] {safety.relative_to(ROOT)}")

shutil.copy2(source, APP)

print(f"[RESTORED] {source.relative_to(ROOT)}")
print("          -> sentinel-react-frontend/src/App.jsx")
print()
print("=" * 78)
print("SOAR rollback completed")
print("=" * 78)
print("This restores the frontend to the state immediately before the")
print("SOAR Korean/balance v5 patch that introduced the black screen.")
print()
print("Next commands:")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
print("  cd ..")
print("  git add sentinel-react-frontend/src/App.jsx")
print('  git commit -m "Rollback SOAR UI runtime regression"')
print("  git push")
