
from pathlib import Path
import shutil
import py_compile
import sys

ROOT = Path.cwd()
MAIN = ROOT / "server" / "main.py"
ENGINE = ROOT / "server" / "response_control_engine.py"

for p in (MAIN, ENGINE):
    if not p.exists():
        print(f"[ERROR] 파일 없음: {p}")
        sys.exit(1)

main = MAIN.read_text(encoding="utf-8")
engine = ENGINE.read_text(encoding="utf-8")

required_engine = [
    "class ResponseControlAction(Base):",
    "target_host = Column(",
    "def create_control_action(",
    "def claim_next_action(",
]
for s in required_engine:
    if s not in engine:
        raise RuntimeError(f"[PRECHECK FAIL] response_control_engine.py: {s}")

required_main = [
    "class ResponseControlCreate(BaseModel):",
    "class ResponseControlClaim(BaseModel):",
    "def queue_response_control(",
    "def claim_response_control(",
    "create_control_action(",
    "claim_next_action(",
]
for s in required_main:
    if s not in main:
        raise RuntimeError(f"[PRECHECK FAIL] main.py: {s}")

print("[PRECHECK OK] SOAR current structure confirmed")

engine_new = engine
main_new = main

if "target_agent_id = Column(" not in engine_new:
    anchor = "    target_host = Column(String, index=True, nullable=True)\n"
    if anchor not in engine_new:
        raise RuntimeError("[PATCH FAIL] target_host column anchor not found")
    engine_new = engine_new.replace(
        anchor,
        anchor + "    target_agent_id = Column(String, index=True, nullable=True)\n",
        1,
    )

if '"target_agent_id": row.target_agent_id' not in engine_new:
    anchor = '        "target_host": row.target_host,\n'
    if anchor not in engine_new:
        raise RuntimeError("[PATCH FAIL] serialize target_host anchor not found")
    engine_new = engine_new.replace(
        anchor,
        anchor + '        "target_agent_id": row.target_agent_id,\n',
        1,
    )

if "target_agent_id: Optional[str] = None" not in engine_new:
    anchor = "    target_host: Optional[str] = None,\n"
    if anchor not in engine_new:
        raise RuntimeError("[PATCH FAIL] create signature target_host anchor not found")
    engine_new = engine_new.replace(
        anchor,
        anchor + "    target_agent_id: Optional[str] = None,\n",
        1,
    )

if "target_agent_id=target_agent_id or None" not in engine_new:
    anchor = "        target_host=target_host or None,\n"
    if anchor not in engine_new:
        raise RuntimeError("[PATCH FAIL] row target_host anchor not found")
    engine_new = engine_new.replace(
        anchor,
        anchor + "        target_agent_id=target_agent_id or None,\n",
        1,
    )

claim_tail = engine_new.split("def claim_next_action", 1)[1]
if "agent_id: Optional[str] = None" not in claim_tail[:600]:
    start = engine_new.find("def claim_next_action(")
    end = engine_new.find("\ndef ", start + 5)
    if start < 0 or end < 0:
        raise RuntimeError("[PATCH FAIL] claim_next_action boundaries missing")

    new_claim = '''def claim_next_action(
    db: Session,
    *,
    hostname: str,
    agent_id: Optional[str] = None,
):
    rows = (
        db.query(ResponseControlAction)
        .filter(ResponseControlAction.status == "QUEUED")
        .order_by(ResponseControlAction.id.asc())
        .limit(50)
        .all()
    )

    hostname_l = (hostname or "").lower()
    agent_id_l = (agent_id or "").lower()

    selected = None

    for row in rows:
        target_agent_id = str(
            getattr(row, "target_agent_id", None) or ""
        ).lower()

        target_host = str(
            row.target_host or ""
        ).lower()

        if target_agent_id:
            if agent_id_l and target_agent_id == agent_id_l:
                selected = row
                break
            continue

        if not target_host or target_host == hostname_l:
            selected = row
            break

    if selected is None:
        return None

    selected.status = "CLAIMED"
    selected.claimed_at = datetime.now()

    db.commit()
    db.refresh(selected)

    return _serialize(selected)
'''
    engine_new = engine_new[:start] + new_claim + engine_new[end:]

if "def migrate_response_control_agent_target(" not in engine_new:
    migration = '''

def migrate_response_control_agent_target(engine):
    from sqlalchemy import inspect, text

    inspector = inspect(engine)

    if "response_control_actions" not in inspector.get_table_names():
        return

    columns = {
        col["name"]
        for col in inspector.get_columns("response_control_actions")
    }

    if "target_agent_id" in columns:
        return

    with engine.begin() as conn:
        conn.execute(
            text(
                "ALTER TABLE response_control_actions "
                "ADD COLUMN target_agent_id VARCHAR"
            )
        )

    print("[DB MIGRATION] response_control_actions.target_agent_id added")
'''
    engine_new = engine_new.rstrip() + migration + "\n"

if "migrate_response_control_agent_target" not in main_new:
    anchor = "    decide_release_request,\n"
    if anchor not in main_new:
        raise RuntimeError("[PATCH FAIL] response_control_engine import anchor missing")
    main_new = main_new.replace(
        anchor,
        anchor + "    migrate_response_control_agent_target,\n",
        1,
    )

old = "from server.endpoint_registry import router as endpoint_registry_router\n"
new = (
    "from server.endpoint_registry import (\n"
    "    router as endpoint_registry_router,\n"
    "    EndpointRegistry,\n"
    ")\n"
)
if "EndpointRegistry," not in main_new:
    if old not in main_new:
        raise RuntimeError("[PATCH FAIL] endpoint_registry import anchor missing")
    main_new = main_new.replace(old, new, 1)

if "migrate_response_control_agent_target(engine)" not in main_new:
    anchor = "Base.metadata.create_all(bind=engine)\n"
    if anchor not in main_new:
        raise RuntimeError("[PATCH FAIL] Base.metadata.create_all anchor missing")
    main_new = main_new.replace(
        anchor,
        anchor + "migrate_response_control_agent_target(engine)\n",
        1,
    )

create_start = main_new.find("class ResponseControlCreate(BaseModel):")
create_end = main_new.find("\n\nclass ", create_start + 1)
create_block = main_new[create_start:create_end]
if "target_agent_id:" not in create_block:
    anchor = "    target_host: Optional[str] = None\n"
    if anchor not in create_block:
        raise RuntimeError("[PATCH FAIL] ResponseControlCreate target_host anchor missing")
    create_block = create_block.replace(
        anchor,
        anchor + "    target_agent_id: Optional[str] = None\n",
        1,
    )
    main_new = main_new[:create_start] + create_block + main_new[create_end:]

claim_model_start = main_new.find("class ResponseControlClaim(BaseModel):")
claim_model_end = main_new.find("\n\nclass ", claim_model_start + 1)
claim_model = main_new[claim_model_start:claim_model_end]
if "agent_id:" not in claim_model:
    anchor = "    hostname: str\n"
    if anchor not in claim_model:
        raise RuntimeError("[PATCH FAIL] ResponseControlClaim hostname anchor missing")
    claim_model = claim_model.replace(
        anchor,
        anchor + "    agent_id: Optional[str] = None\n",
        1,
    )
    main_new = main_new[:claim_model_start] + claim_model + main_new[claim_model_end:]

queue_start = main_new.find("def queue_response_control(")
queue_end = main_new.find("\n\n@app.", queue_start)
if queue_end < 0:
    raise RuntimeError("[PATCH FAIL] queue endpoint end missing")
queue_block = main_new[queue_start:queue_end]

if "resolved_agent_id" not in queue_block:
    body_anchor = "):\n"
    pos = queue_block.find(body_anchor)
    if pos < 0:
        raise RuntimeError("[PATCH FAIL] queue body anchor missing")
    pos += len(body_anchor)

    resolve_code = '''    resolved_agent_id = (body.target_agent_id or "").strip() or None
    resolved_host = body.target_host

    if not resolved_agent_id:
        endpoint_query = db.query(EndpointRegistry).filter(
            EndpointRegistry.linked_user == body.user
        )

        if resolved_host:
            endpoint_query = endpoint_query.filter(
                EndpointRegistry.hostname == resolved_host
            )

        endpoint = endpoint_query.order_by(
            EndpointRegistry.last_seen_at.desc()
        ).first()

        if endpoint:
            resolved_agent_id = endpoint.agent_id
            resolved_host = endpoint.hostname

'''
    queue_block = queue_block[:pos] + resolve_code + queue_block[pos:]

if "target_agent_id=resolved_agent_id" not in queue_block:
    old_arg = "        target_host=body.target_host,\n"
    new_arg = (
        "        target_host=resolved_host,\n"
        "        target_agent_id=resolved_agent_id,\n"
    )
    if old_arg not in queue_block:
        raise RuntimeError("[PATCH FAIL] queue target_host argument missing")
    queue_block = queue_block.replace(old_arg, new_arg, 1)

main_new = main_new[:queue_start] + queue_block + main_new[queue_end:]

claim_start = main_new.find("def claim_response_control(")
claim_end = main_new.find("\n\n@app.", claim_start)
if claim_end < 0:
    raise RuntimeError("[PATCH FAIL] claim endpoint end missing")
claim_block = main_new[claim_start:claim_end]

if "agent_id=body.agent_id" not in claim_block:
    old_call = "    action = claim_next_action(db, hostname=body.hostname)\n"
    new_call = '''    action = claim_next_action(
        db,
        hostname=body.hostname,
        agent_id=body.agent_id,
    )
'''
    if old_call not in claim_block:
        raise RuntimeError("[PATCH FAIL] claim_next_action call anchor missing")
    claim_block = claim_block.replace(old_call, new_call, 1)

main_new = main_new[:claim_start] + claim_block + main_new[claim_end:]

checks = {
    "engine model": "target_agent_id = Column(" in engine_new,
    "engine serialize": '"target_agent_id": row.target_agent_id' in engine_new,
    "engine create": "target_agent_id=target_agent_id or None" in engine_new,
    "engine claim": "agent_id: Optional[str] = None" in engine_new,
    "engine migration": "def migrate_response_control_agent_target(" in engine_new,
    "main migration": "migrate_response_control_agent_target(engine)" in main_new,
    "main endpoint model": "EndpointRegistry," in main_new,
    "main create model": "target_agent_id: Optional[str] = None" in main_new,
    "main claim model": "agent_id: Optional[str] = None" in main_new,
    "main resolver": "resolved_agent_id" in main_new,
    "main claim pass": "agent_id=body.agent_id" in main_new,
}
failed = [k for k,v in checks.items() if not v]
if failed:
    raise RuntimeError("[VERIFY FAIL] " + ", ".join(failed))

tmp_engine = ROOT / "server" / "__response_control_agent_target_verify__.py"
tmp_main = ROOT / "server" / "__main_agent_target_verify__.py"

try:
    tmp_engine.write_text(engine_new, encoding="utf-8")
    tmp_main.write_text(main_new, encoding="utf-8")
    py_compile.compile(str(tmp_engine), doraise=True)
    py_compile.compile(str(tmp_main), doraise=True)
finally:
    for p in (tmp_engine, tmp_main):
        try:
            p.unlink()
        except Exception:
            pass

print("[VERIFY OK] Python compile")
print("[VERIFY OK] agent_id SOAR targeting")

for p in (ENGINE, MAIN):
    b = p.with_name(p.name + ".before_agent_id_soar")
    if not b.exists():
        shutil.copy2(p, b)
        print(f"[BACKUP] {b.relative_to(ROOT)}")

ENGINE.write_text(engine_new, encoding="utf-8")
MAIN.write_text(main_new, encoding="utf-8")

print("[WRITE] server/response_control_engine.py")
print("[WRITE] server/main.py")
print("[DONE] Central SOAR exact agent_id targeting added")
