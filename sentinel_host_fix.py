from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "server" / "change_verification_engine.py"

if not ENGINE.exists():
    raise FileNotFoundError(f"파일이 없습니다: {ENGINE}")

backup = ENGINE.with_name("change_verification_engine.before_host_dedupe_v4.py")
if not backup.exists():
    shutil.copy2(ENGINE, backup)

text = ENGINE.read_text(encoding="utf-8")

start = text.find("def _extract_candidates(event):")
if start == -1:
    raise RuntimeError("_extract_candidates(event) 함수를 찾지 못했습니다.")

next_def = text.find("\ndef ", start + 1)
if next_def == -1:
    raise RuntimeError("_extract_candidates 다음 함수를 찾지 못했습니다.")

new_func = """def _extract_candidates(event):
    candidates = []

    source_ip = getattr(event, "source_ip", None)
    if source_ip:
        candidates.append(("IP", str(source_ip).strip()))

    process_name = getattr(event, "process_name", None)
    if process_name:
        candidates.append(("PROCESS", str(process_name).strip().lower()))

    device_id = getattr(event, "device_id", None)
    device_name = getattr(event, "device_name", None)
    host = getattr(event, "host", None)
    workstation_name = getattr(event, "workstation_name", None)

    if device_id:
        candidates.append(("DEVICE", str(device_id).strip()))
    elif device_name:
        candidates.append(("DEVICE", str(device_name).strip()))
    elif host and workstation_name:
        host_value = str(host).strip()
        workstation_value = str(workstation_name).strip()

        # HOST와 WORKSTATION이 실제로 서로 다른 경우에만
        # 별도 HOST 행동 변화로 검증한다.
        # workstation_name이 없으면 확장 엔진이 host를 WORKSTATION으로
        # 사용하므로 여기서는 HOST를 추가하지 않는다.
        if host_value.lower() != workstation_value.lower():
            candidates.append(("HOST", host_value))

    result = []
    seen = set()

    for item in candidates:
        if not item[1] or item in seen:
            continue

        seen.add(item)
        result.append(item)

    return result
"""

text = text[:start] + new_func + text[next_def:]

compile(text, str(ENGINE), "exec")
ENGINE.write_text(text, encoding="utf-8")

print("=" * 72)
print("[완료] HOST / WORKSTATION 중복 검증 제거 v4")
print("=" * 72)
print("[동작] workstation_name 없음 -> HOST 검증 생성 안 함")
print("[동작] host == workstation_name -> HOST 검증 생성 안 함")
print("[동작] host != workstation_name -> HOST 별도 검증")
print("[검사] change_verification_engine.py 문법 정상")
