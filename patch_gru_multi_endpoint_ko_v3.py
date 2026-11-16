
from pathlib import Path
import shutil
import py_compile
import sys

ROOT = Path.cwd()
INF = ROOT / "server" / "next_action_inference.py"
MAIN = ROOT / "server" / "main.py"
ENG = ROOT / "server" / "threat_prediction_engine.py"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
CSS = ROOT / "sentinel-react-frontend" / "src" / "styles.css"

for p in (INF, MAIN, ENG, APP, CSS):
    if not p.exists():
        print(f"[ERROR] missing: {p}")
        sys.exit(1)

for p in (INF, MAIN, ENG, APP, CSS):
    b = p.with_name(p.name + ".before_gru_multi_endpoint_ko_v3")
    if not b.exists():
        shutil.copy2(p, b)
        print(f"[BACKUP] {b.relative_to(ROOT)}")

# 1) inference
text = INF.read_text(encoding="utf-8")

old_sig = """def predict_next_actions_for_user(
    db,
    SecurityEvent,
    *,
    user: str,
    top_k: int = 3,
    reference_time=None,
) -> dict:
"""
new_sig = """def predict_next_actions_for_user(
    db,
    SecurityEvent,
    *,
    user: str,
    top_k: int = 3,
    reference_time=None,
    host: str | None = None,
    agent_id: str | None = None,
) -> dict:
"""
if old_sig in text:
    text = text.replace(old_sig, new_sig, 1)
    print("[PATCH] inference accepts host / agent_id")
elif "agent_id: str | None = None" in text:
    print("[SKIP] inference scope parameters already present")
else:
    raise RuntimeError("predict_next_actions_for_user signature not found")

old_query = """    query = db.query(SecurityEvent).filter(SecurityEvent.user == user)
    if reference_time is not None:
        query = query.filter(SecurityEvent.timestamp <= reference_time)
"""
new_query = """    query = db.query(SecurityEvent).filter(SecurityEvent.user == user)

    if host:
        query = query.filter(SecurityEvent.host == host)

    if agent_id:
        query = query.filter(SecurityEvent.agent_id == agent_id)

    if reference_time is not None:
        query = query.filter(SecurityEvent.timestamp <= reference_time)
"""
if old_query in text:
    text = text.replace(old_query, new_query, 1)
    print("[PATCH] inference sequence is endpoint-scoped")
elif "query = query.filter(SecurityEvent.agent_id == agent_id)" in text:
    print("[SKIP] endpoint-scoped inference already present")
else:
    raise RuntimeError("inference query anchor not found")

old_tail = """    result["user"] = user
    result["recent_events"] = [_event_payload(event, action) for event, action in mapped]
    return result
"""
new_tail = """    result["user"] = user
    result["host"] = host
    result["agent_id"] = agent_id
    result["recent_events"] = [_event_payload(event, action) for event, action in mapped]
    return result
"""
if old_tail in text:
    text = text.replace(old_tail, new_tail, 1)
    print("[PATCH] inference response includes endpoint identity")
elif 'result["agent_id"] = agent_id' in text:
    print("[SKIP] inference identity response already present")
else:
    raise RuntimeError("inference response tail not found")

INF.write_text(text, encoding="utf-8")
py_compile.compile(str(INF), doraise=True)
print("[COMPILE OK] server/next_action_inference.py")

# 2) main API
text = MAIN.read_text(encoding="utf-8")

old_endpoint = """@app.get("/next-action/predict/{user}")
def get_next_action_prediction(
    user: str,
    top_k: int = 3,
    db: Session = Depends(get_db),
):
    # GRU probability is separate from Threat Progression evidence confidence.
    top_k = max(1, min(int(top_k), 10))
    return predict_next_actions_for_user(
        db,
        SecurityEvent,
        user=user,
        top_k=top_k,
    )
"""
new_endpoint = """@app.get("/next-action/predict/{user}")
def get_next_action_prediction(
    user: str,
    top_k: int = 3,
    host: Optional[str] = None,
    agent_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    # GRU probability is separate from Threat Progression evidence confidence.
    # Sequence scope is user + endpoint when host/agent_id are supplied.
    top_k = max(1, min(int(top_k), 10))
    return predict_next_actions_for_user(
        db,
        SecurityEvent,
        user=user,
        top_k=top_k,
        host=(host or None),
        agent_id=(agent_id or None),
    )
"""
if old_endpoint in text:
    text = text.replace(old_endpoint, new_endpoint, 1)
    print("[PATCH] scoped GRU prediction API")
elif "agent_id: Optional[str] = None" in text and '@app.get("/next-action/predict/{user}")' in text:
    print("[SKIP] scoped GRU API already present")
else:
    raise RuntimeError("GRU prediction endpoint block not found")

if '@app.get("/next-action/endpoints")' not in text:
    marker = '@app.get("/next-action/predict/{user}")'
    idx = text.find(marker)
    if idx < 0:
        raise RuntimeError("GRU endpoint insertion anchor not found")
    endpoint_list_code = """@app.get("/next-action/endpoints")
def get_next_action_endpoints(
    limit: int = 100,
    db: Session = Depends(get_db),
):
    safe_limit = max(1, min(int(limit or 100), 500))

    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user.isnot(None))
        .order_by(SecurityEvent.id.desc())
        .limit(5000)
        .all()
    )

    seen = set()
    items = []

    for event in rows:
        user = str(getattr(event, "user", "") or "").strip()
        host = str(getattr(event, "host", "") or "").strip()
        agent_id = str(getattr(event, "agent_id", "") or "").strip()
        endpoint_ip = str(getattr(event, "endpoint_ip", "") or "").strip()

        if not user:
            continue

        key = (user, agent_id or "", host or "")
        if key in seen:
            continue
        seen.add(key)

        items.append({
            "user": user,
            "host": host or None,
            "agent_id": agent_id or None,
            "endpoint_ip": endpoint_ip or None,
            "last_event_at": getattr(event, "timestamp", None),
            "last_event_id": getattr(event, "id", None),
        })

        if len(items) >= safe_limit:
            break

    return {
        "items": items,
        "count": len(items),
    }


"""
    text = text[:idx] + endpoint_list_code + text[idx:]
    print("[PATCH] GET /next-action/endpoints added")
else:
    print("[SKIP] endpoint list API already present")

MAIN.write_text(text, encoding="utf-8")
py_compile.compile(str(MAIN), doraise=True)
print("[COMPILE OK] server/main.py")

# 3) threat progression scope
text = ENG.read_text(encoding="utf-8")
old_call = """        gru_next_action = predict_next_actions_for_user(
            db,
            SecurityEvent,
            user=user,
            top_k=3,
            reference_time=reference_time,
        )
"""
new_call = """        gru_next_action = predict_next_actions_for_user(
            db,
            SecurityEvent,
            user=user,
            top_k=3,
            reference_time=reference_time,
            host=(target_host or None),
        )
"""
if old_call in text:
    text = text.replace(old_call, new_call, 1)
    print("[PATCH] Threat Progression GRU uses target_host scope")
elif "host=(target_host or None)" in text:
    print("[SKIP] Threat Progression host scope already present")
else:
    raise RuntimeError("Threat Progression GRU call not found")

ENG.write_text(text, encoding="utf-8")
py_compile.compile(str(ENG), doraise=True)
print("[COMPILE OK] server/threat_prediction_engine.py")

# 4) React
app = APP.read_text(encoding="utf-8")
start = app.find("function SoarControlPage(){")
if start < 0:
    raise RuntimeError("SoarControlPage not found")

anchor = '  const[liveGru,setLiveGru]=useState(null)\n'
addition = """  const[gruEndpoints,setGruEndpoints]=useState([])
  const[selectedGruEndpoint,setSelectedGruEndpoint]=useState('')
"""
if "const[gruEndpoints,setGruEndpoints]" not in app[start:]:
    if anchor not in app[start:]:
        raise RuntimeError("liveGru state anchor not found")
    app = app.replace(anchor, anchor + addition, 1)
    print("[PATCH] endpoint selector state added")

helpers = r"""  const gruActionKo={
    LOGIN_SUCCESS:'로그인 성공',
    LOGIN_FAILURE:'로그인 실패',
    LOGOFF:'로그오프',
    FILE_ACCESS:'파일 접근',
    SENSITIVE_FILE_ACCESS:'민감 문서 접근',
    MASS_FILE_ACCESS:'대량 파일 접근',
    USB_CONNECT:'USB 연결',
    USB_ACTIVITY:'USB 사용',
    USB_COPY:'USB 파일 복사',
    PROCESS_EXECUTION:'프로세스 실행',
    POWERSHELL:'PowerShell 실행',
    SCRIPT_EXECUTION:'스크립트 실행',
    ARCHIVE_CREATE:'압축 파일 생성',
    EMAIL_SEND:'이메일 전송',
    WEB_UPLOAD:'웹 업로드',
    EXTERNAL_TRANSFER:'외부 전송',
    NETWORK_ACCESS:'네트워크 접근',
    PRIVILEGED_LOGON:'관리자 권한 로그인',
    EXPLICIT_CREDENTIAL_LOGON:'명시적 자격증명 로그인',
    WORKSTATION_LOCK:'PC 잠금',
    WORKSTATION_UNLOCK:'PC 잠금 해제',
    AUTH_TICKET:'인증 티켓',
    OTHER:'기타 행동'
  }

  const responseLevelKo={
    OBSERVE:'관찰',
    ENHANCED_MONITORING:'강화 모니터링',
    PREPARE_CONTROL:'제어 준비',
    SELECTIVE_PREVENT:'선별적 차단'
  }

  const endpointKey=e=>[
    e?.user||'',
    e?.host||'',
    e?.agent_id||''
  ].join('|||')

  const endpointLabel=e=>{
    const user=e?.user||'사용자 미상'
    const host=e?.host||'Host 미상'
    const ip=e?.endpoint_ip?` · ${e.endpoint_ip}`:''
    return `${host} / ${user}${ip}`
  }

  const parseEndpointKey=key=>{
    const[user='',host='',agent_id='']=String(key||'').split('|||')
    return{user,host,agent_id}
  }

"""
if "const gruActionKo={" not in app[start:]:
    pos = app.find("  const load=async()=>{\n", start)
    if pos < 0:
        raise RuntimeError("load() anchor not found")
    app = app[:pos] + helpers + app[pos:]
    print("[PATCH] Korean labels and endpoint helpers added")

old_gru_load = """    try{
      const gruData=await call('/next-action/predict/siem_demo?top_k=3')
      setLiveGru(gruData?.available?gruData:null)
    }catch(e){
      setLiveGru(null)
    }
"""
new_gru_load = """    try{
      const endpointData=await call('/next-action/endpoints?limit=100')
      const endpointItems=arr(endpointData,['items','value','endpoints'])
      setGruEndpoints(endpointItems)

      let targetKey=selectedGruEndpoint
      if(!targetKey&&endpointItems.length){
        const preferred=
          endpointItems.find(e=>String(e?.user||'')==='siem_demo')
          ||endpointItems[0]
        targetKey=endpointKey(preferred)
        setSelectedGruEndpoint(targetKey)
      }

      if(targetKey){
        const target=parseEndpointKey(targetKey)
        const params=new URLSearchParams({top_k:'3'})
        if(target.host)params.set('host',target.host)
        if(target.agent_id)params.set('agent_id',target.agent_id)

        const gruData=await call(
          `/next-action/predict/${encodeURIComponent(target.user)}?${params.toString()}`
        )
        setLiveGru(gruData?.available?gruData:null)
      }else{
        setLiveGru(null)
      }
    }catch(e){
      setLiveGru(null)
    }
"""
if old_gru_load in app:
    app = app.replace(old_gru_load, new_gru_load, 1)
    print("[PATCH] live GRU now follows selected endpoint")
elif "call('/next-action/endpoints?limit=100')" in app[start:]:
    print("[SKIP] endpoint-aware polling already present")
else:
    raise RuntimeError("live GRU polling block not found")

old_effect = """  useEffect(()=>{
    load()
    const id=setInterval(load,3000)
    return()=>clearInterval(id)
  },[])
"""
new_effect = """  useEffect(()=>{
    load()
    const id=setInterval(load,3000)
    return()=>clearInterval(id)
  },[selectedGruEndpoint])
"""
if old_effect in app:
    app = app.replace(old_effect, new_effect, 1)
    print("[PATCH] polling refreshes when endpoint changes")
elif "},[selectedGruEndpoint])" in app[start:]:
    print("[SKIP] endpoint-aware effect already present")
else:
    raise RuntimeError("SOAR polling effect not found")

old_latest = """  const latestThreatPrediction=[...predictions]
    .sort((a,b)=>num(b.id)-num(a.id))[0]||null
"""
new_latest = """  const selectedGruIdentity=parseEndpointKey(selectedGruEndpoint)

  const latestThreatPrediction=[...predictions]
    .filter(p=>
      (!selectedGruIdentity.user||String(p?.user||'')===selectedGruIdentity.user)
      &&(!selectedGruIdentity.host||String(p?.target_host||'')===selectedGruIdentity.host)
    )
    .sort((a,b)=>num(b.id)-num(a.id))[0]||null
"""
if old_latest in app:
    app = app.replace(old_latest, new_latest, 1)
    print("[PATCH] Threat Progression matched to selected endpoint")
elif "selectedGruIdentity=parseEndpointKey" in app[start:]:
    print("[SKIP] selected endpoint ThreatPrediction matching already present")
else:
    raise RuntimeError("latestThreatPrediction block not found")

app = app.replace("<SectionHeader>GRU Next Action Prediction</SectionHeader>", "<SectionHeader>AI 다음 행동 예측</SectionHeader>", 1)
app = app.replace('<div className="gru-next-eyebrow">LEARNED NEXT-ACTION SIGNAL</div>', '<div className="gru-next-eyebrow">사용자 행동 시퀀스 기반 GRU 예측</div>', 1)
app = app.replace("{latestGruTop1?.action||'예측 준비 중'}", "{gruActionKo[latestGruTop1?.action]||latestGruTop1?.action||'예측 준비 중'}", 1)

panel_anchor = """    <div className="gru-next-action-panel">
      {latestGru?.available
"""
selector = """    <div className="gru-next-action-panel">
      <div className="gru-endpoint-toolbar">
        <div>
          <span className="gru-endpoint-label">분석 대상 Endpoint</span>
          <strong>{endpointLabel(
            gruEndpoints.find(e=>endpointKey(e)===selectedGruEndpoint)
            ||parseEndpointKey(selectedGruEndpoint)
          )}</strong>
        </div>
        <select
          className="gru-endpoint-select"
          value={selectedGruEndpoint}
          onChange={e=>setSelectedGruEndpoint(e.target.value)}
        >
          {gruEndpoints.map(e=>
            <option key={endpointKey(e)} value={endpointKey(e)}>
              {endpointLabel(e)}
            </option>
          )}
        </select>
      </div>

      {latestGru?.available
"""
if "gru-endpoint-toolbar" not in app:
    if panel_anchor not in app:
        raise RuntimeError("GRU panel anchor not found")
    app = app.replace(panel_anchor, selector, 1)
    print("[PATCH] endpoint selector UI added")

old_sub = "                  사용자 {latestGru.user||latestGruPrediction?.user||'-'} · 최근 행동 {latestGru.sequence_length_used??'-'}개 기반\n"
new_sub = "                  사용자 {latestGru.user||'-'} · Endpoint {latestGru.host||'미지정'} · 최근 행동 {latestGru.sequence_length_used??'-'}개 기반\n"
if old_sub in app:
    app = app.replace(old_sub, new_sub, 1)

for old, new in {
    "<span>다음 행동 확률</span>": "<span>예상 확률</span>",
    "<span>Evidence Confidence</span>": "<span>공격 진행 신뢰도</span>",
    "<small>현재 공격 진행 근거의 강도</small>": "<small>현재 공격 단계 판단 근거의 신뢰도</small>",
    "<span>GRU Risk Probability</span>": "<span>위험 행동 예측 확률</span>",
    "<small>Top-3 중 최대 위험행동 확률</small>": "<small>예측 Top-3 중 위험 행동의 최대 확률</small>",
    "<span>Threat Progress 기여</span>": "<span>AI 위험도 반영</span>",
    "<small>GRU 보조 신호 가산점</small>": "<small>GRU 예측이 공격 진행도에 더한 점수</small>",
    "<span>Threat Progress</span>": "<span>공격 진행도</span>",
}.items():
    app = app.replace(old, new, 1)

app = app.replace(
    "<small>{latestGruPrediction?.response_level||'현재 저장된 Threat Progression 없음'}</small>",
    "<small>{latestGruPrediction?.response_level?responseLevelKo[latestGruPrediction.response_level]||latestGruPrediction.response_level:'현재 저장된 공격 진행 정보 없음'}</small>",
    1,
)

app = app.replace(
    '<div className="gru-top3-action">{p.action||\'-\'}</div>',
    '<div className="gru-top3-action">{gruActionKo[p.action]||p.action||\'-\'}</div>',
    1,
)

old_note = """              GRU 확률은 Predictive Threat Progression의 Evidence Confidence와 별도 값입니다.
              GRU는 단독 차단 판단이 아니라 기존 Rule · UEBA · Sequence · Risk 판단을 보조합니다.
"""
new_note = """              GRU 모델은 선택한 사용자·Endpoint의 최근 행동 순서를 분석해 다음 행동을 예측합니다.
              '위험 행동 예측 확률'과 '공격 진행 신뢰도'는 서로 다른 값이며,
              AI 예측은 단독 차단이 아니라 기존 Rule · UEBA · Sequence · Risk 판단을 보조합니다.
"""
if old_note in app:
    app = app.replace(old_note, new_note, 1)

APP.write_text(app, encoding="utf-8")
print("[WRITE] sentinel-react-frontend/src/App.jsx")

# 5) CSS
css = CSS.read_text(encoding="utf-8")
if ".gru-endpoint-toolbar{" not in css:
    css += r"""

/* ===== SENTINEL GRU MULTI-ENDPOINT V3 ===== */
.gru-endpoint-toolbar{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:18px;
  margin:-2px 0 16px;
  padding:12px 14px;
  border:1px solid rgba(255,255,255,.065);
  border-radius:11px;
  background:rgba(255,255,255,.025);
}
.gru-endpoint-toolbar>div{min-width:0}
.gru-endpoint-label{
  display:block;
  margin-bottom:5px;
  color:#7d858f;
  font-size:9px;
}
.gru-endpoint-toolbar strong{
  display:block;
  overflow:hidden;
  color:#dce1e7;
  font-size:11px;
  font-weight:650;
  text-overflow:ellipsis;
  white-space:nowrap;
}
.gru-endpoint-select{
  width:min(390px,46%);
  min-height:34px;
  padding:0 10px;
  border:1px solid rgba(255,255,255,.10);
  border-radius:8px;
  outline:none;
  background:#171b20;
  color:#dce1e7;
  font-size:10px;
}
@media(max-width:720px){
  .gru-endpoint-toolbar{
    align-items:stretch;
    flex-direction:column;
  }
  .gru-endpoint-select{width:100%}
}
"""
    CSS.write_text(css, encoding="utf-8")
    print("[PATCH] multi-endpoint CSS added")
else:
    print("[SKIP] multi-endpoint CSS already present")

print()
print("=" * 80)
print("SENTINEL GRU Multi-Endpoint + Korean UI v3 installed")
print("=" * 80)
print("- GRU sequence scope: user + host + agent_id")
print("- Threat Progression GRU scope: user + target_host")
print("- Endpoint selector added to SOAR dashboard")
print("- Korean action labels and metric descriptions added")
print("- Selected endpoint only drives Top-3 prediction")
print()
print("Next:")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
