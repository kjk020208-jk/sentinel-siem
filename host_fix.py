from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "server" / "main.py"
ENGINE = ROOT / "server" / "change_verification_engine.py"

for path in (MAIN, ENGINE):
    if not path.exists():
        raise FileNotFoundError(f"필수 파일이 없습니다: {path}")

for path in (MAIN, ENGINE):
    backup = path.with_name(path.stem + ".before_host_workstation_dedupe_v2.py")
    if not backup.exists():
        shutil.copy2(path, backup)

text = ENGINE.read_text(encoding="utf-8")

start = text.find("def _extract_candidates(event):")
if start == -1:
    raise RuntimeError("_extract_candidates(event) 함수를 찾지 못했습니다.")

next_def = text.find("\ndef ", start + 1)
if next_def == -1:
    next_def = len(text)

func = text[start:next_def]

host_line = '    host = getattr(event, "host", None)\n'
work_line = '    workstation_name = getattr(event, "workstation_name", None)\n'
if work_line not in func:
    if host_line not in func:
        raise RuntimeError("_extract_candidates 안에서 host 읽기 코드를 찾지 못했습니다.")
    func = func.replace(host_line, host_line + work_line, 1)

old = '    elif host:\n        candidates.append(("HOST", str(host).strip()))\n'
new = (
    '    elif host:\n'
    '        host_value = str(host).strip()\n'
    '        workstation_value = (\n'
    '            str(workstation_name).strip()\n'
    '            if workstation_name\n'
    '            else None\n'
    '        )\n\n'
    '        # 같은 물리 장비가 HOST와 WORKSTATION으로 동시에 들어오면\n'
    '        # WORKSTATION만 유지하고 HOST 중복 검증은 생략한다.\n'
    '        if (\n'
    '            not workstation_value\n'
    '            or host_value.lower() != workstation_value.lower()\n'
    '        ):\n'
    '            candidates.append(("HOST", host_value))\n'
)

if "같은 물리 장비가 HOST와 WORKSTATION" not in func:
    if old not in func:
        raise RuntimeError("_extract_candidates 안에서 HOST 후보 추가 코드를 찾지 못했습니다.")
    func = func.replace(old, new, 1)

text = text[:start] + func + text[next_def:]
compile(text, str(ENGINE), "exec")
ENGINE.write_text(text, encoding="utf-8")

main = MAIN.read_text(encoding="utf-8")

target = (
    '    change_results = evaluate_behavior_change(\n'
    '        db=db,\n'
    '        event=db_event\n'
    '    )\n'
)
replacement = (
    '    # HOST / WORKSTATION 중복 검증 방지\n'
    '    db_event.workstation_name = getattr(\n'
    '        event,\n'
    '        "workstation_name",\n'
    '        None\n'
    '    )\n\n'
    '    change_results = evaluate_behavior_change(\n'
    '        db=db,\n'
    '        event=db_event\n'
    '    )\n'
)

if "HOST / WORKSTATION 중복 검증 방지" not in main:
    if target not in main:
        raise RuntimeError("main.py에서 evaluate_behavior_change 호출을 찾지 못했습니다.")
    main = main.replace(target, replacement, 1)

compile(main, str(MAIN), "exec")
MAIN.write_text(main, encoding="utf-8")

print("=" * 72)
print("[완료] HOST / WORKSTATION 중복 검증 제거 패치 v2")
print("=" * 72)
print("[수정] host == workstation_name 이면 HOST 후보 제외")
print("[수정] workstation_name을 검증 엔진에 런타임 전달")
print("[유지] HOST와 WORKSTATION이 다르면 둘 다 구분")
print("[유지] DB 스키마 변경 없음")
print("[검사] main.py 문법 정상")
print("[검사] change_verification_engine.py 문법 정상")
