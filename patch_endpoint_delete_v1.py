from pathlib import Path
import py_compile
import shutil
import sys

ROOT = Path.cwd()
REG = ROOT / "server" / "endpoint_registry.py"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

for p in (REG, APP):
    if not p.exists():
        print(f"[ERROR] 파일 없음: {p}")
        sys.exit(1)

reg = REG.read_text(encoding="utf-8")
app = APP.read_text(encoding="utf-8")

if '@router.post("/endpoints/{agent_id}/link")' not in reg:
    raise RuntimeError("[PRECHECK FAIL] endpoint link route not found")

if "function EndpointManagementPage()" not in app:
    raise RuntimeError("[PRECHECK FAIL] EndpointManagementPage not found")

if "<th>사용자 연결</th>" not in app:
    raise RuntimeError("[PRECHECK FAIL] Endpoint table header not found")

print("[PRECHECK OK] current Endpoint Registry structure confirmed")

reg_new = reg

if '@router.delete("/endpoints/{agent_id}")' not in reg_new:
    delete_route = '''

@router.delete("/endpoints/{agent_id}")
def delete_endpoint(
    agent_id: str,
    db: Session = Depends(get_db),
):
    row = (
        db.query(EndpointRegistry)
        .filter(EndpointRegistry.agent_id == agent_id)
        .first()
    )

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Endpoint를 찾을 수 없습니다.",
        )

    hostname = row.hostname
    linked_user = row.linked_user

    db.delete(row)
    db.commit()

    return {
        "ok": True,
        "agent_id": agent_id,
        "hostname": hostname,
        "linked_user": linked_user,
    }
'''
    reg_new = reg_new.rstrip() + delete_route + "\n"

app_new = app

if "const deleteEndpoint=async(agentId,hostname)=>{" not in app_new:
    anchor = "  const onlineCount=rows.filter(row=>row.status==='ONLINE').length\n"
    if anchor not in app_new:
        raise RuntimeError("[PATCH FAIL] onlineCount anchor not found")

    fn = '''  const deleteEndpoint=async(agentId,hostname)=>{
    const target=hostname||agentId

    if(!window.confirm(
      `${target} Endpoint를 삭제하시겠습니까?`
    )){
      return
    }

    setBusy(agentId)
    setMsg('')
    setErr('')

    try{
      const response=await fetch(
        `${API}/endpoints/${encodeURIComponent(agentId)}`,
        {
          method:'DELETE',
          credentials:'include'
        }
      )

      const data=await response.json().catch(()=>({}))

      if(!response.ok){
        throw new Error(
          data.detail||
          `Endpoint 삭제 실패 (${response.status})`
        )
      }

      setMsg(
        `${target} Endpoint 삭제 완료`
      )

      await load()
    }catch(error){
      setErr(error.message)
    }finally{
      setBusy('')
    }
  }

'''
    app_new = app_new.replace(anchor, fn + anchor, 1)

if "<th>관리</th>" not in app_new:
    old = "            <th>사용자 연결</th>\n          </tr>"
    new = "            <th>사용자 연결</th>\n            <th>관리</th>\n          </tr>"
    if old not in app_new:
        raise RuntimeError("[PATCH FAIL] table header anchor not found")
    app_new = app_new.replace(old, new, 1)

if 'title="Endpoint 삭제"' not in app_new:
    old = '''                <td>
                  <select
                    value={row.linked_user||''}
                    disabled={busy===row.agent_id}
                    onChange={event=>linkEndpoint(row.agent_id,event.target.value)}
                  >
                    <option value="">사용자 선택</option>

                    {users.map(user=>{
                      const username=user.username||user.user||''
                      if(!username)return null

                      return (
                        <option key={username} value={username}>
                          {user.display_name||username} / {username}
                        </option>
                      )
                    })}
                  </select>
                </td>
              </tr>'''

    new = '''                <td>
                  <select
                    value={row.linked_user||''}
                    disabled={busy===row.agent_id}
                    onChange={event=>linkEndpoint(row.agent_id,event.target.value)}
                  >
                    <option value="">사용자 선택</option>

                    {users.map(user=>{
                      const username=user.username||user.user||''
                      if(!username)return null

                      return (
                        <option key={username} value={username}>
                          {user.display_name||username} / {username}
                        </option>
                      )
                    })}
                  </select>
                </td>

                <td>
                  <button
                    type="button"
                    className="btn ghost"
                    disabled={busy===row.agent_id}
                    onClick={()=>deleteEndpoint(row.agent_id,row.hostname)}
                    title="Endpoint 삭제"
                  >
                    삭제
                  </button>
                </td>
              </tr>'''

    if old not in app_new:
        raise RuntimeError("[PATCH FAIL] Endpoint row select block not found")
    app_new = app_new.replace(old, new, 1)

app_new = app_new.replace(
    'colSpan="9" className="empty-cell"',
    'colSpan="10" className="empty-cell"',
    1,
)

if '@router.delete("/endpoints/{agent_id}")' not in reg_new:
    raise RuntimeError("[VERIFY FAIL] delete route missing")

if "const deleteEndpoint=async(agentId,hostname)=>{" not in app_new:
    raise RuntimeError("[VERIFY FAIL] deleteEndpoint missing")

if 'title="Endpoint 삭제"' not in app_new:
    raise RuntimeError("[VERIFY FAIL] delete button missing")

tmp = ROOT / "server" / "__endpoint_registry_delete_verify__.py"
tmp.write_text(reg_new, encoding="utf-8")
try:
    py_compile.compile(str(tmp), doraise=True)
finally:
    try:
        tmp.unlink()
    except Exception:
        pass

print("[VERIFY OK] backend compile")
print("[VERIFY OK] frontend delete UI anchors")

for p in (REG, APP):
    backup = p.with_name(p.name + ".before_endpoint_delete")
    if not backup.exists():
        shutil.copy2(p, backup)
        print(f"[BACKUP] {backup.relative_to(ROOT)}")

REG.write_text(reg_new, encoding="utf-8")
APP.write_text(app_new, encoding="utf-8")

print("[WRITE] server/endpoint_registry.py")
print("[WRITE] sentinel-react-frontend/src/App.jsx")
print("[DONE] Endpoint delete feature added")
print("NEXT: cd sentinel-react-frontend && npm.cmd run build")
