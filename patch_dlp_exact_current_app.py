from pathlib import Path
import shutil, py_compile

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
ENGINE = ROOT / "server" / "response_control_engine.py"

if not APP.exists():
    raise SystemExit(f"[ERROR] missing: {APP}")
if not ENGINE.exists():
    raise SystemExit(f"[ERROR] missing: {ENGINE}")

for p in (APP, ENGINE):
    backup = p.with_name(p.name + ".before_dlp_exact")
    if not backup.exists():
        shutil.copy2(p, backup)

app = APP.read_text(encoding="utf-8")
engine = ENGINE.read_text(encoding="utf-8")

# ============================================================
# 1) OverviewV2 - exact current code
# ============================================================
old = """  const latestRiskEventForAlertV2=events.find(e=>['HIGH','CRITICAL'].includes(String(e.risk_level||'').toUpperCase()))||null
  const latestRiskAlertIdV2=String(latestRiskEventForAlertV2?.id??latestRiskEventForAlertV2?.event_id??'')
  useEffect(()=>{if(latestRiskAlertIdV2)setOverviewV2AckEventId('')},[latestRiskAlertIdV2])
"""
new = """  const latestRiskEventForAlertV2=events.find(e=>['HIGH','CRITICAL'].includes(String(e.risk_level||'').toUpperCase()))||null
  const latestRiskAlertIdV2=String(latestRiskEventForAlertV2?.id??latestRiskEventForAlertV2?.event_id??'')
  const ALERT_ACK_KEY='sentinel_acknowledged_security_events_v1'

  const isAlertAcknowledged=(()=>{
    try{
      const ids=JSON.parse(localStorage.getItem(ALERT_ACK_KEY)||'[]')
      return Array.isArray(ids)&&ids.map(String).includes(latestRiskAlertIdV2)
    }catch{
      return false
    }
  })()

  const acknowledgeCurrentAlert=()=>{
    try{
      const raw=JSON.parse(localStorage.getItem(ALERT_ACK_KEY)||'[]')
      const ids=Array.isArray(raw)?raw.map(String):[]
      if(!ids.includes(latestRiskAlertIdV2))ids.push(latestRiskAlertIdV2)
      localStorage.setItem(ALERT_ACK_KEY,JSON.stringify(ids.slice(-200)))
    }catch{}
    setOverviewV2AckEventId(latestRiskAlertIdV2)
  }

  const openCurrentAlertDetail=()=>{
    if(!latestRiskEventForAlertV2)return
    acknowledgeCurrentAlert()

    const eventId=String(latestRiskEventForAlertV2.id??latestRiskEventForAlertV2.event_id??'')
    sessionStorage.setItem('sentinel_focus_event_id',eventId)

    const incidentIds=[]
    if(Array.isArray(latestIncident?.event_ids))incidentIds.push(...latestIncident.event_ids)
    if(Array.isArray(latestIncident?.related_event_ids))incidentIds.push(...latestIncident.related_event_ids)
    if(Array.isArray(latestIncident?.storyline)){
      latestIncident.storyline.forEach(s=>incidentIds.push(s?.event_id??s?.id))
    }

    const belongsToLatestIncident=incidentIds.some(x=>String(x)===eventId)
    if(belongsToLatestIncident){
      const iid=String(latestIncident?.id??latestIncident?.incident_id??'')
      if(iid)sessionStorage.setItem('sentinel_focus_incident_id',iid)
      setPage('incidents')
    }else{
      sessionStorage.removeItem('sentinel_focus_incident_id')
      setPage('events')
    }
  }

  const openCurrentAlertSoar=()=>{
    if(!latestRiskEventForAlertV2)return
    acknowledgeCurrentAlert()
    sessionStorage.setItem(
      'sentinel_soar_event_context',
      JSON.stringify(latestRiskEventForAlertV2)
    )
    setPage('soar')
  }
"""
if old not in app:
    raise RuntimeError("OverviewV2 alert state block not found")
app = app.replace(old, new, 1)

old = "{latestRiskEventForAlertV2&&latestRiskAlertIdV2!==overviewV2AckEventId&&("
new = "{latestRiskEventForAlertV2&&!isAlertAcknowledged&&latestRiskAlertIdV2!==overviewV2AckEventId&&("
if old not in app:
    raise RuntimeError("OverviewV2 alert visibility condition not found")
app = app.replace(old, new, 1)

old = """            <button className="btn danger" onClick={()=>setPage('events')}>{'이벤트 상세 확인'}</button>
            <button className="btn ghost" onClick={()=>setOverviewV2AckEventId(latestRiskAlertIdV2)}>{'확인'}</button>"""
new = """            <button className="btn danger" onClick={openCurrentAlertDetail}>{'이벤트 상세 확인'}</button>
            <button className="btn primary" onClick={openCurrentAlertSoar}>{'SOAR 즉시 대응'}</button>
            <button className="btn ghost" onClick={acknowledgeCurrentAlert}>{'확인'}</button>"""
if old not in app:
    raise RuntimeError("OverviewV2 exact alert buttons not found")
app = app.replace(old, new, 1)

# ============================================================
# 2) EventsPage - exact current signature
# ============================================================
old = """function EventsPage({events,monitoredUsers=[],summary}){
  const[level,setLevel]=useState('전체'),[user,setUser]=useState('전체'),[type,setType]=useState('전체'),[search,setSearch]=useState(''),[selectedBehavior,setSelectedBehavior]=useState(''),[selectedExplain,setSelectedExplain]=useState(''),[explanation,setExplanation]=useState(null),[exErr,setExErr]=useState(''),[eventAI,setEventAI]=useState(null),[eventAiError,setEventAiError]=useState(''),[aiBusy,setAiBusy]=useState(false)
"""
new = """function EventsPage({events,monitoredUsers=[],summary}){
  const[level,setLevel]=useState('전체'),[user,setUser]=useState('전체'),[type,setType]=useState('전체'),[search,setSearch]=useState(''),[selectedBehavior,setSelectedBehavior]=useState(''),[selectedExplain,setSelectedExplain]=useState(''),[explanation,setExplanation]=useState(null),[exErr,setExErr]=useState(''),[eventAI,setEventAI]=useState(null),[eventAiError,setEventAiError]=useState(''),[aiBusy,setAiBusy]=useState(false)

  useEffect(()=>{
    const focusId=sessionStorage.getItem('sentinel_focus_event_id')
    if(!focusId)return

    const target=events.find(e=>String(e.id??e.event_id)===String(focusId))
    if(!target)return

    setLevel('전체')
    setUser('전체')
    setType('전체')
    setSearch('')
    setSelectedExplain(String(focusId))
    setExplanation(null)
    setEventAI(null)
    setExErr('')

    api.riskExplanation(focusId)
      .then(setExplanation)
      .catch(e=>setExErr(e.message))
  },[])
"""
if old not in app:
    raise RuntimeError("Exact EventsPage header not found")
app = app.replace(old, new, 1)

# ============================================================
# 3) IncidentsPage - exact current signature/state
# ============================================================
old = """function IncidentsPage({incidents,allEvents=[],initialId}){
  const[level,setLevel]=useState('전체'),[status,setStatus]=useState('전체'),[id,setId]=useState(initialId||incidents[0]?.id||''),[detail,setDetail]=useState(null),[err,setErr]=useState(''),[ai,setAi]=useState(null),[incidentAiError,setIncidentAiError]=useState(''),[aiBusy,setAiBusy]=useState(false),[playbook,setPlaybook]=useState(null),[selectedEvent,setSelectedEvent]=useState(''),[eventExplain,setEventExplain]=useState(null),[eventAI,setEventAI]=useState(null),[eventAiError,setEventAiError]=useState(''),[eventAiBusy,setEventAiBusy]=useState(false)
"""
new = """function IncidentsPage({incidents,allEvents=[],initialId}){
  const[level,setLevel]=useState('전체'),[status,setStatus]=useState('전체'),[id,setId]=useState(initialId||incidents[0]?.id||''),[detail,setDetail]=useState(null),[err,setErr]=useState(''),[ai,setAi]=useState(null),[incidentAiError,setIncidentAiError]=useState(''),[aiBusy,setAiBusy]=useState(false),[playbook,setPlaybook]=useState(null),[selectedEvent,setSelectedEvent]=useState(''),[eventExplain,setEventExplain]=useState(null),[eventAI,setEventAI]=useState(null),[eventAiError,setEventAiError]=useState(''),[eventAiBusy,setEventAiBusy]=useState(false)

  useEffect(()=>{
    const focusIncident=sessionStorage.getItem('sentinel_focus_incident_id')
    if(focusIncident)setId(String(focusIncident))
  },[])
"""
if old not in app:
    raise RuntimeError("Exact IncidentsPage header not found")
app = app.replace(old, new, 1)

old = "      if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))"
new = """      const focusEvent=sessionStorage.getItem('sentinel_focus_event_id')
      const focused=focusEvent&&ev.find(x=>String(x.id||x.event_id)===String(focusEvent))
      if(focused)setSelectedEvent(String(focused.id||focused.event_id))
      else if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))"""
if old not in app:
    raise RuntimeError("Incident selected-event line not found")
app = app.replace(old, new, 1)

# ============================================================
# 4) SOAR page - exact current signature
# ============================================================
old = """function SoarControlPage(){
  const SOAR_API='https://api.sentineljk.co.kr'
"""
new = """function SoarControlPage(){
  const SOAR_API='https://api.sentineljk.co.kr'
  const[alertContext]=useState(()=>{
    try{
      return JSON.parse(sessionStorage.getItem('sentinel_soar_event_context')||'null')
    }catch{
      return null
    }
  })
"""
if old not in app:
    raise RuntimeError("Exact SoarControlPage header not found")
app = app.replace(old, new, 1)

old = """  const call=async(path,options={})=>{"""
new = """  const queueDlpProcessTerminate=async()=>{
    if(!alertContext||busy)return

    const process=String(alertContext.process_name||'').toLowerCase()
    const allowed=[
      'chrome.exe','msedge.exe','firefox.exe','brave.exe',
      'opera.exe','outlook.exe','olk.exe','thunderbird.exe'
    ]

    if(!allowed.includes(process)){
      setErr(`실제 종료 지원 대상 프로세스가 아닙니다: ${process||'-'}`)
      return
    }

    setBusy('dlp-process-terminate')
    setMsg('')
    setErr('')

    try{
      const result=await call('/response-controls',{
        method:'POST',
        body:JSON.stringify({
          user:alertContext.user||'siem_demo',
          action_type:'PROCESS_TERMINATE',
          operation:'APPLY',
          reason:`DLP_WEB_UPLOAD_BLOCK process=${process} event_id=${alertContext.id??alertContext.event_id??''}`,
          risk_score:Math.round(num(alertContext.risk_score)),
          requested_by:'DLP_ALERT_ADMIN'
        })
      })

      setMsg(`실제 프로세스 종료 제어가 Agent 큐에 등록되었습니다. Action #${result?.action?.id??'-'} · ${process}`)
      await load()
    }catch(e){
      setErr(e.message)
    }finally{
      setBusy('')
    }
  }

  const call=async(path,options={})=>{"""
if old not in app:
    raise RuntimeError("SOAR call function anchor not found")
app = app.replace(old, new, 1)

# Add context banner immediately after the first return(<> in SOAR component only
soar_start = app.find("function SoarControlPage(){")
if soar_start < 0:
    raise RuntimeError("SoarControlPage start missing after patch")
soar_end = app.find("\nfunction ", soar_start + 1)
if soar_end < 0:
    soar_end = len(app)
soar = app[soar_start:soar_end]

if "DLP 대응 대상 이벤트" not in soar:
    marker = "return <>"
    idx = soar.find(marker)
    if idx < 0:
        marker = "return (<>"
        idx = soar.find(marker)
    if idx < 0:
        marker = "return(\n    <>"
        idx = soar.find(marker)

    if idx >= 0:
        insert_pos = idx + len(marker)
        card = """{alertContext&&<Notice type="warning"><b>DLP 대응 대상 이벤트 · Event #{alertContext.id??alertContext.event_id??'-'}</b><br/>{alertContext.user||'-'} {'·'} {koEvent(alertContext.event_type)} {'·'} Risk {num(alertContext.risk_score).toFixed(2)} {'·'} {alertContext.process_name||'-'}<div className="alert-actions"><button className="btn danger" disabled={Boolean(busy)} onClick={queueDlpProcessTerminate}>{busy==='dlp-process-terminate'?'제어 요청 중...':'탐지 프로세스 즉시 종료'}</button></div></Notice>}"""
        soar = soar[:insert_pos] + card + soar[insert_pos:]
        app = app[:soar_start] + soar + app[soar_end:]
    else:
        raise RuntimeError("SOAR return anchor not found")

# ============================================================
# 5) Backend action type
# ============================================================
if 'PROCESS_TERMINATE' not in engine:
    old = 'VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT"}'
    new = 'VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT", "PROCESS_TERMINATE"}'
    if old not in engine:
        raise RuntimeError("VALID_ACTION_TYPES anchor not found")
    engine = engine.replace(old, new, 1)

# ============================================================
# 6) Verification before write
# ============================================================
checks = [
    ("persistent ack", "sentinel_acknowledged_security_events_v1" in app),
    ("SOAR alert button", "SOAR 즉시 대응" in app),
    ("event focus", "sentinel_focus_event_id" in app),
    ("incident focus", "sentinel_focus_incident_id" in app),
    ("soar context", "sentinel_soar_event_context" in app),
    ("soar terminate queue", "queueDlpProcessTerminate" in app),
    ("backend PROCESS_TERMINATE", "PROCESS_TERMINATE" in engine),
]

failed = [name for name, ok in checks if not ok]
if failed:
    raise RuntimeError("VERIFY FAILED: " + ", ".join(failed))

APP.write_text(app, encoding="utf-8")
ENGINE.write_text(engine, encoding="utf-8")
py_compile.compile(str(ENGINE), doraise=True)

print("[VERIFY OK] persistent alert acknowledgement")
print("[VERIFY OK] exact event/incident drilldown")
print("[VERIFY OK] SOAR alert context + PROCESS_TERMINATE")
print("[COMPILE OK] server/response_control_engine.py")
print("[WRITE] sentinel-react-frontend/src/App.jsx")
print("[WRITE] server/response_control_engine.py")
