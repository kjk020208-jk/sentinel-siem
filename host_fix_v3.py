from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "server" / "main.py"
ENGINE = ROOT / "server" / "change_verification_engine.py"

for p in (MAIN, ENGINE):
    if not p.exists():
        raise FileNotFoundError(f"필수 파일이 없습니다: {p}")

# 백업
for p in (MAIN, ENGINE):
    b = p.with_name(p.stem + ".before_host_dedupe_v3.py")
    if not b.exists():
        shutil.copy2(p, b)

# ------------------------------------------------------------
# change_verification_engine.py: _extract_candidates 함수 전체 교체
# ------------------------------------------------------------
text = ENGINE.read_text(encoding="utf-8")
start = text.find("def _extract_candidates(event):")
if start == -1:
    raise RuntimeError("_extract_candidates(event) 함수를 찾지 못했습니다.")

next_def = text.find("\ndef ", start + 1)
if next_def == -1:
    raise RuntimeError("_extract_candidates 다음 함수를 찾지 못했습니다.")

new_func = '''def _extract_candidates(event):
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
    elif host:
        host_value = str(host).strip()
        workstation_value = (
            str(workstation_name).strip()
            if workstation_name
            else None
        )

        # 동일 장비가 HOST와 WORKSTATION으로 중복되면 HOST는 생략
        if (
            not workstation_value
            or host_value.lower() != workstation_value.lower()
        ):
            candidates.append(("HOST", host_value))

    result = []
    seen = set()
    for item in candidates:
        if not item[1] or item in seen:
            continue
        seen.add(item)
        result.append(item)

    return result
'''

text = text[:start] + new_func + text[next_def:]
compile(text, str(ENGINE), "exec")
ENGINE.write_text(text, encoding="utf-8")

# ------------------------------------------------------------
# main.py: workstation_name을 db_event 런타임 속성으로 전달
# ------------------------------------------------------------
main = MAIN.read_text(encoding="utf-8")

if "HOST / WORKSTATION 중복 검증 방지" not in main:
    target = (
        "    change_results = evaluate_behavior_change(\n"
        "        db=db,\n"
        "        event=db_event\n"
        "    )\n"
    )

    if target not in main:
        raise RuntimeError("main.py에서 evaluate_behavior_change 호출을 찾지 못했습니다.")

    replacement = (
        "    # HOST / WORKSTATION 중복 검증 방지\n"
        "    db_event.workstation_name = getattr(\n"
        "        event,\n"
        "        \"workstation_name\",\n"
        "        None\n"
        "    )\n\n"
        "    change_results = evaluate_behavior_change(\n"
        "        db=db,\n"
        "        event=db_event\n"
        "    )\n"
    )

    main = main.replace(target, replacement, 1)

compile(main, str(MAIN), "exec")
MAIN.write_text(main, encoding="utf-8")

print("=" * 72)
print("[완료] HOST / WORKSTATION 중복 검증 제거 v3")
print("=" * 72)
print("[검사] change_verification_engine.py 문법 정상")
print("[검사] main.py 문법 정상")
print("[동작] host == workstation_name 이면 HOST 검증 생략")
print("[동작] 둘이 다르면 HOST와 WORKSTATION을 구분")
