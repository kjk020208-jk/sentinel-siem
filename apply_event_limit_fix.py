from pathlib import Path
import shutil
import py_compile

ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "server" / "main.py"

dashboard_candidates = [
    ROOT / "dashboard" / "app_beforealert.py",
    ROOT / "app_beforealert.py",
    ROOT / "app_risk_receipt_final.py",
]

def patch_main(path: Path):
    text = path.read_text(encoding="utf-8")

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
    # CERT 대용량 검증 데이터는 DB에 그대로 보존하고,
    # 대시보드에는 최신 이벤트만 빠르게 제공한다.
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

    if new in text:
        print("[SKIP] server/main.py 이미 limit 적용됨")
        return

    if old not in text:
        raise RuntimeError("server/main.py에서 /events 기존 코드를 찾지 못했습니다.")

    backup = path.with_name("main.before_event_limit.py")
    shutil.copy2(path, backup)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"[완료] {path.relative_to(ROOT)} 수정")
    print(f"[백업] {backup.relative_to(ROOT)}")


def patch_dashboard(path: Path):
    text = path.read_text(encoding="utf-8")

    old = '''        response = requests.get(
            f"{API_URL}/events",
            timeout=5
        )
'''

    new = '''        response = requests.get(
            f"{API_URL}/events",
            params={"limit": 500},
            timeout=10
        )
'''

    if new in text:
        print(f"[SKIP] {path.relative_to(ROOT)} 이미 limit 적용됨")
        return True

    if old not in text:
        return False

    backup = path.with_name(path.stem + ".before_event_limit" + path.suffix)
    shutil.copy2(path, backup)
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"[완료] {path.relative_to(ROOT)} 수정")
    print(f"[백업] {backup.relative_to(ROOT)}")
    return True


if not MAIN.exists():
    raise FileNotFoundError(f"server/main.py를 찾을 수 없습니다: {MAIN}")

patch_main(MAIN)

patched_dashboard = False
for candidate in dashboard_candidates:
    if candidate.exists():
        if patch_dashboard(candidate):
            patched_dashboard = True

if not patched_dashboard:
    raise FileNotFoundError(
        "대시보드 파일을 찾지 못했습니다. "
        "dashboard/app_beforealert.py, app_beforealert.py, app_risk_receipt_final.py 중 하나가 필요합니다."
    )

py_compile.compile(str(MAIN), doraise=True)
print("[검사] server/main.py 문법 정상")

for candidate in dashboard_candidates:
    if candidate.exists():
        try:
            py_compile.compile(str(candidate), doraise=True)
            print(f"[검사] {candidate.relative_to(ROOT)} 문법 정상")
        except Exception as e:
            print(f"[주의] {candidate.relative_to(ROOT)} 문법 검사 실패: {e}")

print()
print("[완료] 최근 500건만 대시보드에 불러오도록 수정했습니다.")
print("FastAPI와 Streamlit을 둘 다 재시작하세요.")
