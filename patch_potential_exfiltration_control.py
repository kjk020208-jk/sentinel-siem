from pathlib import Path
import shutil
import sys
import py_compile

ROOT = Path.cwd()
ENGINE = ROOT / "server" / "threat_prediction_engine.py"

if not ENGINE.exists():
    print("[ERROR] server/threat_prediction_engine.py를 찾지 못했습니다.")
    print(r"프로젝트 루트 C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
    sys.exit(1)

backup = ENGINE.with_name("threat_prediction_engine.before_potential_exfiltration_fix.py")
if not backup.exists():
    shutil.copy2(ENGINE, backup)
    print(f"[BACKUP] {backup.relative_to(ROOT)}")

text = ENGINE.read_text(encoding="utf-8")

old = "    if vector == 'USB_EXFILTRATION' and sensitive and usb and progress >= AUTO_PROGRESS_THRESHOLD and confidence >= AUTO_CONFIDENCE_THRESHOLD:\n        recommended_control = 'USB_WRITE_RESTRICT'\n"

new = """    if (
        vector in {'USB_EXFILTRATION', 'POTENTIAL_EXFILTRATION'}
        and sensitive
        and usb
        and progress >= AUTO_PROGRESS_THRESHOLD
        and confidence >= AUTO_CONFIDENCE_THRESHOLD
    ):
        recommended_control = 'USB_WRITE_RESTRICT'
"""

if old in text:
    text = text.replace(old, new, 1)
    print("[PATCH] POTENTIAL_EXFILTRATION도 USB_WRITE_RESTRICT 추천 대상으로 확장")
elif "vector in {'USB_EXFILTRATION', 'POTENTIAL_EXFILTRATION'}" in text:
    print("[SKIP] 이미 수정되어 있습니다.")
else:
    raise RuntimeError("추천 제어 조건 블록을 찾지 못했습니다.")

ENGINE.write_text(text, encoding="utf-8")
py_compile.compile(str(ENGINE), doraise=True)

print("[COMPILE OK] server/threat_prediction_engine.py")
print()
print("=" * 72)
print("Predictive Exfiltration Control Fix 완료")
print("=" * 72)
print(" - USB_EXFILTRATION -> 기존대로 제어 가능")
print(" - POTENTIAL_EXFILTRATION -> 고신뢰 조건 충족 시 제어 가능")
print(" - Progress / Confidence / Host guard 조건은 그대로 유지")
