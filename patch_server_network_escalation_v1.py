from pathlib import Path
import py_compile

TARGET = Path.cwd() / "server" / "threat_prediction_engine.py"

if not TARGET.exists():
    raise SystemExit(f"[ERROR] 파일 없음: {TARGET}")

text = TARGET.read_text(encoding="utf-8")
original = text

if "SENTINEL_NETWORK_RESTRICT_PROGRESS" in text:
    print("[SKIP] NETWORK_RESTRICT 예측 정책이 이미 적용되어 있습니다.")
    py_compile.compile(str(TARGET), doraise=True)
    raise SystemExit(0)

needle_candidates = [
    "AUTO_CONFIDENCE_THRESHOLD = int(os.getenv(\'SENTINEL_AUTO_MICRO_CONTROL_CONFIDENCE\', \'85\'))",
    'AUTO_CONFIDENCE_THRESHOLD = int(os.getenv("SENTINEL_AUTO_MICRO_CONTROL_CONFIDENCE", "85"))',
]
needle = next((x for x in needle_candidates if x in text), None)
if not needle:
    raise RuntimeError("[PATCH FAIL] AUTO_CONFIDENCE_THRESHOLD 선언을 찾지 못했습니다.")

addition = needle + "\nNETWORK_RESTRICT_PROGRESS_THRESHOLD = int(os.getenv(\'SENTINEL_NETWORK_RESTRICT_PROGRESS\', \'96\'))\nNETWORK_RESTRICT_CONFIDENCE_THRESHOLD = int(os.getenv(\'SENTINEL_NETWORK_RESTRICT_CONFIDENCE\', \'95\'))\n"
text = text.replace(needle, addition, 1)

usb_markers = [
    "recommended_control = \'USB_WRITE_RESTRICT\'",
    'recommended_control = "USB_WRITE_RESTRICT"',
]
marker = next((x for x in usb_markers if x in text), None)
if not marker:
    raise RuntimeError("[PATCH FAIL] USB_WRITE_RESTRICT 추천 로직을 찾지 못했습니다.")

pos = text.find(marker)
line_start = text.rfind("\n", 0, pos) + 1
line_end = text.find("\n", pos)
if line_end == -1:
    line_end = len(text)
indent = text[line_start:pos]

network_block = (
    f"{indent}# Progressive Escalation\n"
    f"{indent}if (\n"
    f"{indent}    vector in {{\'USB_EXFILTRATION\', \'POTENTIAL_EXFILTRATION\'}}\n"
    f"{indent}    and sensitive\n"
    f"{indent}    and progress >= NETWORK_RESTRICT_PROGRESS_THRESHOLD\n"
    f"{indent}    and confidence >= NETWORK_RESTRICT_CONFIDENCE_THRESHOLD\n"
    f"{indent}):\n"
    f"{indent}    recommended_control = \'NETWORK_RESTRICT\'\n"
)
text = text[:line_end + 1] + network_block + text[line_end + 1:]

backup = TARGET.with_suffix(".py.bak_network_restrict")
if not backup.exists():
    backup.write_text(original, encoding="utf-8")

TARGET.write_text(text, encoding="utf-8")
py_compile.compile(str(TARGET), doraise=True)

required = ["NETWORK_RESTRICT_PROGRESS_THRESHOLD", "NETWORK_RESTRICT_CONFIDENCE_THRESHOLD", "recommended_control = \'NETWORK_RESTRICT\'"]
missing = [x for x in required if x not in text]
if missing:
    raise RuntimeError(f"[VERIFY FAIL] 누락: {missing}")

print(f"[BACKUP] {backup}")
print(f"[WRITE] {TARGET}")
print("[COMPILE OK] server/threat_prediction_engine.py")
print("[VERIFY OK] 96%/95% NETWORK_RESTRICT escalation added")
