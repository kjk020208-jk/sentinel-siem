
from pathlib import Path
import py_compile
import shutil
import sys

ROOT = Path.cwd()
REG = ROOT / "server" / "endpoint_registry.py"
MAIN = ROOT / "server" / "main.py"
AUTH = ROOT / "server" / "auth.py"

for p in (REG, MAIN, AUTH):
    if not p.exists():
        print(f"[ERROR] 파일 없음: {p}")
        sys.exit(1)

reg = REG.read_text(encoding="utf-8")
main = MAIN.read_text(encoding="utf-8")
auth = AUTH.read_text(encoding="utf-8")

if 'router = APIRouter()' not in reg:
    raise RuntimeError("[PRECHECK FAIL] endpoint_registry router missing")
if 'AGENT_TOKEN = os.getenv("SENTINEL_AGENT_TOKEN"' not in reg:
    raise RuntimeError("[PRECHECK FAIL] AGENT_TOKEN config missing")
if 'request.url.path == "/agent/register"' not in main:
    raise RuntimeError("[PRECHECK FAIL] main agent register exception missing")
if 'path == "/agent/register"' not in auth:
    raise RuntimeError("[PRECHECK FAIL] auth agent register exception missing")

print("[PRECHECK OK] current Endpoint Registry auth structure confirmed")

reg_new = reg
main_new = main
auth_new = auth

if 'ENROLLMENT_TOKEN = os.getenv("SENTINEL_ENROLLMENT_TOKEN"' not in reg_new:
    anchor = 'AGENT_TOKEN = os.getenv("SENTINEL_AGENT_TOKEN", "").strip()\n'
    reg_new = reg_new.replace(
        anchor,
        anchor + 'ENROLLMENT_TOKEN = os.getenv("SENTINEL_ENROLLMENT_TOKEN", "").strip()\n',
        1,
    )

if "class AgentEnroll(BaseModel):" not in reg_new:
    anchor = "class AgentRegister(BaseModel):\n"
    idx = reg_new.find(anchor)
    if idx < 0:
        raise RuntimeError("[PATCH FAIL] AgentRegister anchor missing")
    enroll_model = (
        "class AgentEnroll(BaseModel):\n"
        "    enrollment_code: str\n\n\n"
    )
    reg_new = reg_new[:idx] + enroll_model + reg_new[idx:]

if '@router.post("/agent/enroll")' not in reg_new:
    anchor = '@router.post("/agent/register")\n'
    idx = reg_new.find(anchor)
    if idx < 0:
        raise RuntimeError("[PATCH FAIL] register route anchor missing")
    route = (
        '@router.post("/agent/enroll")\n'
        'def enroll_agent(body: AgentEnroll):\n'
        '    if not ENROLLMENT_TOKEN:\n'
        '        raise HTTPException(\n'
        '            status_code=503,\n'
        '            detail="Agent Enrollment가 서버에서 활성화되지 않았습니다.",\n'
        '        )\n\n'
        '    supplied = (body.enrollment_code or "").strip()\n\n'
        '    if not supplied or not secrets.compare_digest(\n'
        '        supplied,\n'
        '        ENROLLMENT_TOKEN,\n'
        '    ):\n'
        '        raise HTTPException(\n'
        '            status_code=401,\n'
        '            detail="유효하지 않은 Enrollment Code입니다.",\n'
        '        )\n\n'
        '    if not AGENT_TOKEN:\n'
        '        raise HTTPException(\n'
        '            status_code=503,\n'
        '            detail="SENTINEL_AGENT_TOKEN이 설정되지 않았습니다.",\n'
        '        )\n\n'
        '    return {\n'
        '        "ok": True,\n'
        '        "agent_token": AGENT_TOKEN,\n'
        '    }\n\n\n'
    )
    reg_new = reg_new[:idx] + route + reg_new[idx:]

if 'request.url.path == "/agent/enroll"' not in main_new:
    anchor = '        or request.url.path == "/agent/register"\n'
    if anchor not in main_new:
        raise RuntimeError("[PATCH FAIL] main register auth anchor missing")
    main_new = main_new.replace(
        anchor,
        '        or request.url.path == "/agent/enroll"\n' + anchor,
        1,
    )

if 'path == "/agent/enroll"' not in auth_new:
    anchor = '            or path == "/agent/register"\n'
    if anchor not in auth_new:
        raise RuntimeError("[PATCH FAIL] auth register anchor missing")
    auth_new = auth_new.replace(
        anchor,
        '            or path == "/agent/enroll"\n' + anchor,
        1,
    )

checks = {
    "enroll env": 'SENTINEL_ENROLLMENT_TOKEN' in reg_new,
    "enroll model": "class AgentEnroll" in reg_new,
    "enroll route": '@router.post("/agent/enroll")' in reg_new,
    "main exception": 'request.url.path == "/agent/enroll"' in main_new,
    "auth exception": 'path == "/agent/enroll"' in auth_new,
}
failed = [k for k,v in checks.items() if not v]
if failed:
    raise RuntimeError("[VERIFY FAIL] " + ", ".join(failed))

temps = [
    (ROOT / "server" / "__endpoint_registry_enroll_verify__.py", reg_new),
    (ROOT / "server" / "__main_enroll_verify__.py", main_new),
    (ROOT / "server" / "__auth_enroll_verify__.py", auth_new),
]
try:
    for p, content in temps:
        p.write_text(content, encoding="utf-8")
        py_compile.compile(str(p), doraise=True)
finally:
    for p, _ in temps:
        try:
            p.unlink()
        except Exception:
            pass

print("[VERIFY OK] Python compile")
print("[VERIFY OK] /agent/enroll")

for p in (REG, MAIN, AUTH):
    b = p.with_name(p.name + ".before_agent_enrollment")
    if not b.exists():
        shutil.copy2(p, b)
        print(f"[BACKUP] {b.relative_to(ROOT)}")

REG.write_text(reg_new, encoding="utf-8")
MAIN.write_text(main_new, encoding="utf-8")
AUTH.write_text(auth_new, encoding="utf-8")

print("[WRITE] server/endpoint_registry.py")
print("[WRITE] server/main.py")
print("[WRITE] server/auth.py")
print("[DONE] Agent Enrollment endpoint added")
print("Railway web 환경변수에 SENTINEL_ENROLLMENT_TOKEN 추가 필요")
