from pathlib import Path
import shutil

path = Path("server/baseline_engine.py")
if not path.exists():
    raise SystemExit("server/baseline_engine.py 파일을 찾을 수 없습니다.")

backup = Path("server/baseline_engine.before_change_verification.py")
if not backup.exists():
    shutil.copy2(path, backup)

text = path.read_text(encoding="utf-8")

import_line = "from server.change_verification_engine import is_event_allowed_for_baseline\n"
anchor = "from server.models import SecurityEvent, MonitoredUser\n"
if import_line not in text:
    if anchor not in text:
        raise SystemExit("models import 위치를 찾지 못했습니다.")
    text = text.replace(anchor, anchor + import_line, 1)

old = """    return (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp >= learning_since,
            SecurityEvent.timestamp < reference_time,
            SecurityEvent.risk_level == LEARNING_RISK_LEVEL
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )
"""

new = """    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp >= learning_since,
            SecurityEvent.timestamp < reference_time,
            SecurityEvent.risk_level == LEARNING_RISK_LEVEL
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    return [
        event
        for event in events
        if is_event_allowed_for_baseline(db, event)
    ]
"""

if new not in text:
    if old not in text:
        raise SystemExit("_get_learning_events() return 블록을 찾지 못했습니다.")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
print("[완료] server/baseline_engine.py 수정")
print("[백업]", backup)
