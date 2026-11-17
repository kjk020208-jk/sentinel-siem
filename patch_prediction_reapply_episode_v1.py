from pathlib import Path
import py_compile

TARGET = Path.cwd() / "server" / "threat_prediction_engine.py"

if not TARGET.exists():
    raise SystemExit(f"[ERROR] 파일 없음: {TARGET}")

text = TARGET.read_text(encoding="utf-8")
original = text

start = text.find("def _control_active_or_pending(")
if start == -1:
    raise RuntimeError(
        "[PATCH FAIL] _control_active_or_pending()를 찾지 못했습니다. "
        "현재 threat_prediction_engine.py를 확인하세요."
    )

end_candidates = [
    text.find("\ndef _usb_control_active_or_pending", start),
    text.find("\ndef evaluate_threat_prediction", start),
]
end_candidates = [x for x in end_candidates if x != -1]

if not end_candidates:
    raise RuntimeError("[PATCH FAIL] helper 함수 끝 위치를 찾지 못했습니다.")

end = min(end_candidates)

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

    pending_stale_after = timedelta(
        seconds=max(
            30,
            int(
                os.getenv(
                    'SENTINEL_CONTROL_PENDING_STALE_SECONDS',
                    '180'
                )
            )
        )
    )

    completed_apply_hold = timedelta(
        seconds=max(
            30,
            int(
                os.getenv(
                    'SENTINEL_COMPLETED_APPLY_HOLD_SECONDS',
                    '300'
                )
            )
        )
    )

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
                and now - activity_time <= pending_stale_after
            ):
                return True

    pending_releases = [
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

    if latest_completed.operation == 'RELEASE':
        return False

    if latest_completed.completed_at is not None:
        age = now - latest_completed.completed_at

        if age <= completed_apply_hold:
            return True

    return False
'''

text = text[:start] + new_helper + text[end:]

backup = TARGET.with_suffix(".py.bak_episode_control")
if not backup.exists():
    backup.write_text(original, encoding="utf-8")

TARGET.write_text(text, encoding="utf-8")
py_compile.compile(str(TARGET), doraise=True)

checks = [
    "SENTINEL_COMPLETED_APPLY_HOLD_SECONDS",
    "pending_releases",
    "latest_completed.operation == 'RELEASE'",
    "age <= completed_apply_hold",
]

missing = [token for token in checks if token not in text]
if missing:
    raise RuntimeError(f"[VERIFY FAIL] 누락: {missing}")

print(f"[BACKUP] {backup}")
print(f"[WRITE]  {TARGET}")
print("[COMPILE OK] server/threat_prediction_engine.py")
print("[VERIFY OK] completed APPLY no longer blocks future episodes forever")
print("[DEFAULT] pending stale = 180s")
print("[DEFAULT] completed APPLY hold = 300s")
