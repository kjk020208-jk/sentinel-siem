from pathlib import Path
import py_compile

TARGET = Path.cwd() / "server" / "threat_prediction_engine.py"

if not TARGET.exists():
    raise SystemExit(f"[ERROR] 파일 없음: {TARGET}")

text = TARGET.read_text(encoding="utf-8")
original = text

old = '''    pending_releases = [
        row for row in rows
        if (
            row.operation == 'RELEASE'
            and row.status in {
                'AWAITING_ADMIN',
                'QUEUED',
                'CLAIMED',
            }
        )
    ]

    if pending_releases:
        return True
'''

new = '''    # 오래된 RELEASE 요청이 DB에 남아 있어도
    # 새 공격 Episode의 자동 제어를 영구적으로 막지 않는다.
    #
    # AWAITING_ADMIN / QUEUED / CLAIMED RELEASE도
    # 최근 작업일 때만 실제 해제 진행 상태로 인정한다.
    for row in rows:
        if (
            row.operation == 'RELEASE'
            and row.status in {
                'AWAITING_ADMIN',
                'QUEUED',
                'CLAIMED',
            }
        ):
            release_activity_time = (
                row.claimed_at
                or row.updated_at
                or row.created_at
            )

            if (
                release_activity_time is not None
                and now - release_activity_time <= pending_stale_after
            ):
                return True
'''

if old not in text:
    raise RuntimeError(
        "[PATCH FAIL] 기존 pending_releases 블록을 찾지 못했습니다. "
        "현재 threat_prediction_engine.py가 최신 패치 버전인지 확인하세요."
    )

text = text.replace(old, new, 1)

backup = TARGET.with_suffix(".py.bak_release_stale")
if not backup.exists():
    backup.write_text(original, encoding="utf-8")

TARGET.write_text(text, encoding="utf-8")
py_compile.compile(str(TARGET), doraise=True)

required = [
    "release_activity_time",
    "now - release_activity_time <= pending_stale_after",
    "row.operation == 'RELEASE'",
]
missing = [x for x in required if x not in text]
if missing:
    raise RuntimeError(f"[VERIFY FAIL] 누락: {missing}")

print(f"[BACKUP] {backup}")
print(f"[WRITE]  {TARGET}")
print("[COMPILE OK] server/threat_prediction_engine.py")
print("[VERIFY OK] stale RELEASE requests no longer block future auto-controls")
print("[RULE] RELEASE AWAITING_ADMIN/QUEUED/CLAIMED only blocks while recent")
