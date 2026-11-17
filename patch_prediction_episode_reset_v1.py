from pathlib import Path
import py_compile

TARGET = Path.cwd() / "server" / "threat_prediction_engine.py"

if not TARGET.exists():
    raise SystemExit(f"[ERROR] 파일 없음: {TARGET}")

text = TARGET.read_text(encoding="utf-8")
original = text

if "latest_completed_release" in text:
    print("[SKIP] 제어 해제 후 Prediction episode reset 로직이 이미 적용되어 있습니다.")
    py_compile.compile(str(TARGET), doraise=True)
    raise SystemExit(0)

old_func = """def _recent_user_events(db, user, reference_time, limit=40, minutes=60):
    since = reference_time - timedelta(minutes=minutes)
    rows = (db.query(SecurityEvent)
        .filter(SecurityEvent.user == user, SecurityEvent.timestamp <= reference_time, SecurityEvent.timestamp >= since)
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(limit).all())
    return list(reversed(rows))
"""

new_func = """def _recent_user_events(
    db,
    user,
    reference_time,
    target_host=None,
    limit=40,
    minutes=60,
):
    # 기본적으로 최근 60분을 공격 진행 episode 후보로 사용한다.
    since = reference_time - timedelta(minutes=minutes)

    # 이전 SOAR 제어가 정상적으로 RELEASE 완료됐다면,
    # 그 시점 이전 이벤트는 새 공격 episode에 재사용하지 않는다.
    release_q = (
        db.query(ResponseControlAction)
        .filter(
            ResponseControlAction.user == user,
            ResponseControlAction.operation == 'RELEASE',
            ResponseControlAction.status == 'COMPLETED',
            ResponseControlAction.completed_at.isnot(None),
        )
    )

    if target_host:
        release_q = release_q.filter(
            ResponseControlAction.target_host == target_host
        )

    latest_completed_release = (
        release_q
        .order_by(
            ResponseControlAction.completed_at.desc(),
            ResponseControlAction.id.desc(),
        )
        .first()
    )

    if (
        latest_completed_release is not None
        and latest_completed_release.completed_at is not None
        and latest_completed_release.completed_at > since
    ):
        since = latest_completed_release.completed_at

    rows = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp <= reference_time,
            SecurityEvent.timestamp > since,
        )
        .order_by(
            SecurityEvent.timestamp.desc(),
            SecurityEvent.id.desc(),
        )
        .limit(limit)
        .all()
    )

    return list(reversed(rows))
"""

if old_func not in text:
    raise RuntimeError(
        "[PATCH FAIL] _recent_user_events() 기존 블록을 찾지 못했습니다. "
        "현재 파일 버전을 확인하세요."
    )

text = text.replace(old_func, new_func, 1)

old_call = "events = _recent_user_events(db, user, reference_time)"
new_call = """events = _recent_user_events(
        db,
        user,
        reference_time,
        target_host=target_host,
    )"""

if old_call not in text:
    raise RuntimeError(
        "[PATCH FAIL] _recent_user_events() 호출부를 찾지 못했습니다."
    )

text = text.replace(old_call, new_call, 1)

backup = TARGET.with_suffix(".py.bak_episode_reset")
if not backup.exists():
    backup.write_text(original, encoding="utf-8")

TARGET.write_text(text, encoding="utf-8")
py_compile.compile(str(TARGET), doraise=True)

checks = [
    "latest_completed_release",
    "ResponseControlAction.operation == 'RELEASE'",
    "ResponseControlAction.status == 'COMPLETED'",
    "target_host=target_host",
    "SecurityEvent.timestamp > since",
]

missing = [x for x in checks if x not in text]
if missing:
    raise RuntimeError(f"[VERIFY FAIL] 누락: {missing}")

print(f"[BACKUP] {backup}")
print(f"[WRITE]  {TARGET}")
print("[COMPILE OK] server/threat_prediction_engine.py")
print("[VERIFY OK] completed RELEASE resets predictive attack episode")
