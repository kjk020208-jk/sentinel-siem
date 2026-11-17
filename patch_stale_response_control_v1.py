from pathlib import Path
import py_compile

TARGET = Path.cwd() / "server" / "threat_prediction_engine.py"

if not TARGET.exists():
    raise SystemExit(f"[ERROR] 파일 없음: {TARGET}")

text = TARGET.read_text(encoding="utf-8")
original = text

if "CONTROL_PENDING_STALE_SECONDS" in text:
    print("[SKIP] stale response-control 보호 로직이 이미 적용되어 있습니다.")
    py_compile.compile(str(TARGET), doraise=True)
    raise SystemExit(0)

anchor = "NETWORK_RESTRICT_CONFIDENCE_THRESHOLD = int(os.getenv('SENTINEL_NETWORK_RESTRICT_CONFIDENCE', '95'))"
if anchor not in text:
    raise RuntimeError("[PATCH FAIL] NETWORK_RESTRICT_CONFIDENCE_THRESHOLD 위치를 찾지 못했습니다.")

replacement = anchor + "\n\n# QUEUED / CLAIMED 작업이 Agent 장애나 재배포로 고아 상태가 된 경우\n# 새 Prediction 제어를 영구적으로 막지 않도록 하는 만료 시간.\nCONTROL_PENDING_STALE_SECONDS = int(\n    os.getenv('SENTINEL_CONTROL_PENDING_STALE_SECONDS', '180')\n)\n"
text = text.replace(anchor, replacement, 1)

start = text.find("def _control_active_or_pending(")
end = text.find("\ndef _usb_control_active_or_pending", start)

if start == -1 or end == -1:
    raise RuntimeError("[PATCH FAIL] _control_active_or_pending() 블록을 찾지 못했습니다. 최신 threat_prediction_engine.py인지 확인하세요.")

new_helper = '''def _control_active_or_pending(db, target_host, action_type):
    action_type = str(action_type or '').upper().strip()

    q = db.query(ResponseControlAction).filter(
        ResponseControlAction.action_type == action_type
    )

    if target_host:
        q = q.filter(
            ResponseControlAction.target_host == target_host
        )

    rows = (
        q.order_by(ResponseControlAction.id.desc())
        .limit(50)
        .all()
    )

    now = datetime.now()
    stale_after = timedelta(
        seconds=max(30, CONTROL_PENDING_STALE_SECONDS)
    )

    # 최근 QUEUED / CLAIMED만 실제 대기 작업으로 인정한다.
    # 오래된 고아 작업은 새 자동 제어 생성을 막지 않는다.
    for row in rows:
        if (
            row.operation == 'APPLY'
            and row.status in {'QUEUED', 'CLAIMED'}
        ):
            activity_time = (
                row.claimed_at
                or row.updated_at
                or row.created_at
            )

            if (
                activity_time is not None
                and now - activity_time <= stale_after
            ):
                return True

    # 완료된 APPLY / RELEASE는 최신 완료 시각으로 실제 상태를 판단한다.
    completed = [
        row for row in rows
        if (
            row.status == 'COMPLETED'
            and row.operation in {'APPLY', 'RELEASE'}
            and row.completed_at is not None
        )
    ]

    if not completed:
        return False

    latest_completed = max(
        completed,
        key=lambda row: (
            row.completed_at,
            row.id,
        ),
    )

    return latest_completed.operation == 'APPLY'
'''

text = text[:start] + new_helper + text[end:]

backup = TARGET.with_suffix(".py.bak_stale_control")
if not backup.exists():
    backup.write_text(original, encoding="utf-8")

TARGET.write_text(text, encoding="utf-8")
py_compile.compile(str(TARGET), doraise=True)

required_tokens = [
    "CONTROL_PENDING_STALE_SECONDS",
    "stale_after = timedelta",
    "latest_completed.operation == 'APPLY'",
    "row.status in {'QUEUED', 'CLAIMED'}",
]
missing = [token for token in required_tokens if token not in text]
if missing:
    raise RuntimeError(f"[VERIFY FAIL] 누락: {missing}")

print(f"[BACKUP] {backup}")
print(f"[WRITE]  {TARGET}")
print("[COMPILE OK] server/threat_prediction_engine.py")
print("[VERIFY OK] stale QUEUED/CLAIMED no longer block new controls forever")
print("[DEFAULT] stale timeout = 180 seconds")
