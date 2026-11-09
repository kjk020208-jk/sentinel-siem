from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "server" / "main.py"
ENGINE = ROOT / "server" / "change_verification_engine.py"

for path in (MAIN, ENGINE):
    if not path.exists():
        raise FileNotFoundError(f"필수 파일이 없습니다: {path}")

for path in (MAIN, ENGINE):
    backup = path.with_name(path.stem + ".before_host_workstation_dedupe.py")
    if not backup.exists():
        shutil.copy2(path, backup)

text = ENGINE.read_text(encoding="utf-8")

old_block = """    device_id = getattr(event, "device_id", None)
    device_name = getattr(event, "device_name", None)
    host = getattr(event, "host", None)

    if device_id:
        candidates.append(("DEVICE", str(device_id).strip()))
    elif device_name:
        candidates.append(("DEVICE", str(device_name).strip()))
    elif host:
        candidates.append(("HOST", str(host).strip()))
"""

new_block = """    device_id = getattr(event, "device_id", None)
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

        # 같은 장비가 HOST와 WORKSTATION으로 동시에 들어오면
        # WORKSTATION만 유지하고 HOST 중복 검증은 생략한다.
        if (
            not workstation_value
            or host_value.lower() != workstation_value.lower()
        ):
            candidates.append(("HOST", host_value))
"""

if old_block not in text:
    raise RuntimeError("change_verification_engine.py 장치 후보 블록을 찾지 못했습니다.")

text = text.replace(old_block, new_block, 1)
compile(text, str(ENGINE), "exec")
ENGINE.write_text(text, encoding="utf-8")

main = MAIN.read_text(encoding="utf-8")

marker = """    change_results = evaluate_behavior_change(
        db=db,
        event=db_event
    )
"""

replacement = """    # HOST / WORKSTATION 중복 검증 방지
    db_event.workstation_name = getattr(
        event,
        "workstation_name",
        None
    )

    change_results = evaluate_behavior_change(
        db=db,
        event=db_event
    )
"""

if marker not in main:
    raise RuntimeError("main.py에서 evaluate_behavior_change 호출을 찾지 못했습니다.")

if "HOST / WORKSTATION 중복 검증 방지" not in main:
    main = main.replace(marker, replacement, 1)

compile(main, str(MAIN), "exec")
MAIN.write_text(main, encoding="utf-8")

print("=" * 72)
print("[완료] HOST / WORKSTATION 중복 검증 제거 패치")
print("=" * 72)
print("[수정] host == workstation_name 이면 HOST 후보 제외")
print("[수정] workstation_name을 검증 엔진에 런타임 전달")
print("[유지] 둘이 다르면 각각 구분 가능")
print("[유지] DB 스키마 변경 없음")
print("[검사] 문법 정상")
