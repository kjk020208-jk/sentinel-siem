from pathlib import Path
import shutil
import py_compile

root = Path(__file__).resolve().parent
main_path = root / "server" / "main.py"

text = main_path.read_text(encoding="utf-8")

old = '''@app.get("/events")
def get_events(
    db: Session = Depends(get_db)
):
    events = (
        db.query(SecurityEvent)
        .order_by(
            SecurityEvent.id.desc()
        )
        .all()
    )

    return events
'''

new = '''@app.get("/events")
def get_events(
    limit: int = 500,
    db: Session = Depends(get_db)
):
    safe_limit = max(1, min(int(limit or 500), 5000))

    events = (
        db.query(SecurityEvent)
        .order_by(
            SecurityEvent.id.desc()
        )
        .limit(safe_limit)
        .all()
    )

    return events
'''

if old not in text:
    raise RuntimeError("기존 /events 코드 블록을 찾지 못했습니다.")

backup = root / "server" / "main.before_limit_fix.py"
shutil.copy2(main_path, backup)

main_path.write_text(text.replace(old, new, 1), encoding="utf-8")

py_compile.compile(str(main_path), doraise=True)

print("[완료] server/main.py 수정")
print("[백업] server/main.before_limit_fix.py")
print("[검사] 문법 정상")
print("[적용] /events?limit=5 -> 최대 5건 반환")
