from pathlib import Path
import shutil
import py_compile

TARGET = Path("client/windows_collector.py")
BACKUP = Path("client/windows_collector.before_commandline_fix.py")

if not TARGET.exists():
    raise FileNotFoundError(f"파일을 찾을 수 없습니다: {TARGET}")

code = TARGET.read_text(encoding="utf-8")

if not BACKUP.exists():
    shutil.copy2(TARGET, BACKUP)
    print(f"[백업] {BACKUP}")

old = '''        "process_name": process_name,
        # 4688에서 읽은 상세 실행 정보를 실제 FastAPI payload에도 포함한다.
        # _display는 send_event()에서 제거되므로 분석용 필드는 최상위에 있어야 한다.
        "command_line": command_line,
        "parent_process": parent_process,
        "_display": {
            "title": "4663 중요 파일 접근",
'''

new = '''        "process_name": process_name,
        "_display": {
            "title": "4663 중요 파일 접근",
'''

if old in code:
    code = code.replace(old, new, 1)
    print("[수정] 4663 payload의 잘못된 command_line / parent_process 제거")
else:
    marker = '            "title": "4663 중요 파일 접근",'
    pos = code.find(marker)

    if pos == -1:
        raise RuntimeError(
            "4663 payload 위치를 찾지 못했습니다. "
            "현재 windows_collector.py를 확인해야 합니다."
        )

    block_start = code.rfind("return {", 0, pos)
    block = code[block_start:pos]

    changed = False

    for bad_line in (
        '        "command_line": command_line,\n',
        '        "parent_process": parent_process,\n',
    ):
        if bad_line in block:
            block = block.replace(bad_line, "", 1)
            changed = True

    if changed:
        code = code[:block_start] + block + code[pos:]
        print("[수정] 4663 payload의 잘못된 변수 참조 제거")
    else:
        print("[확인] 4663에는 잘못된 두 필드가 이미 없습니다.")

parse_4688_pos = code.find("def parse_4688")
if parse_4688_pos == -1:
    raise RuntimeError("parse_4688 함수를 찾지 못했습니다.")

next_section = code.find(
    "# ============================================================",
    parse_4688_pos + 20
)
if next_section == -1:
    next_section = len(code)

block_4688 = code[parse_4688_pos:next_section]

required_definition = '''    command_line = get_xml_value(
        root,
        "CommandLine"
    )
'''
if required_definition not in block_4688:
    raise RuntimeError(
        "parse_4688에서 command_line 정의를 찾지 못했습니다."
    )

if '"command_line": command_line' not in block_4688:
    needle = '        "process_name": process_name,\n'
    replacement = (
        '        "process_name": process_name,\n'
        '        "command_line": command_line,\n'
        '        "parent_process": parent_process,\n'
    )

    if needle not in block_4688:
        raise RuntimeError("4688 payload 삽입 위치를 찾지 못했습니다.")

    block_4688 = block_4688.replace(needle, replacement, 1)
    code = (
        code[:parse_4688_pos]
        + block_4688
        + code[next_section:]
    )
    print("[수정] 4688 분석 payload에 command_line / parent_process 추가")
else:
    print("[확인] 4688 command_line / parent_process는 정상")

TARGET.write_text(code, encoding="utf-8")
py_compile.compile(str(TARGET), doraise=True)

print()
print("=" * 70)
print("windows_collector.py 수정 완료")
print("문법 검사: OK")
print("=" * 70)
print("다음 실행:")
print("  python -m client.windows_collector")
