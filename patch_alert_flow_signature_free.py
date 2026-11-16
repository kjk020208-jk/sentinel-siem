from pathlib import Path
import re
import shutil
import py_compile
import sys

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'
ENGINE = ROOT / 'server' / 'response_control_engine.py'

for p in (APP, ENGINE):
    if not p.exists():
        raise SystemExit(f'[ERROR] missing: {p}')
    backup = p.with_name(p.name + '.before_alert_flow_signature_free')
    if not backup.exists():
        shutil.copy2(p, backup)

app = APP.read_text(encoding='utf-8')
engine = ENGINE.read_text(encoding='utf-8')


def component_bounds(text, name):
    m = re.search(rf'function\s+{re.escape(name)}\s*\(', text)
    if not m:
        raise RuntimeError(f'{name} function not found')
    start = m.start()
    nxt = re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(', text[m.end():])
    end = m.end() + nxt.start() if nxt else len(text)
    return start, end


def insert_after(text, anchor, payload, label):
    idx = text.find(anchor)
    if idx < 0:
        raise RuntimeError(f'{label} anchor not found')
    idx += len(anchor)
    return text[:idx] + payload + text[idx:]

# ------------------------------------------------------------------
# 1) App-level helper functions. No component signatures are changed.
# ------------------------------------------------------------------
app_start = app.find('export default function App(){')
sidebar_start = app.find('\nfunction Sidebar', app_start)
if app_start < 0 or sidebar_start < 0:
    raise RuntimeError('App scope not found')

scope = app[app_start:sidebar_start]

if 'const openSecurityAlertDetail=' not in scope:
    anchor = '  const latestIncident=criticalOpen[0]||incidents[0]'
    helper = """
  const openSecurityAlertDetail=event=>{
    const eventId=String(event?.id??event?.event_id??'')
    if(!eventId)return

    sessionStorage.setItem('sentinel_focus_event_id',eventId)

    const matched=incidents.find(i=>{
      const ids=[]
      if(Array.isArray(i.event_ids))ids.push(...i.event_ids)
      if(Array.isArray(i.related_event_ids))ids.push(...i.related_event_ids)
      if(Array.isArray(i.storyline)){
        i.storyline.forEach(s=>ids.push(s?.event_id??s?.id))
      }
      return ids.some(x=>String(x)===eventId)
    })

    if(matched){
      sessionStorage.setItem('sentinel_focus_incident_id',String(matched.id??matched.incident_id??''))
      setPage('incidents')
    }else{
      sessionStorage.removeItem('sentinel_focus_incident_id')
      setPage('events')
    }
  }

  const openSecurityAlertSoar=event=>{
    sessionStorage.setItem('sentinel_soar_event_context',JSON.stringify(event||{}))
    setPage('soar')
  }
"""
    app = insert_after(app, anchor, helper, 'App latestIncident')

app_start = app.find('export default function App(){')
sidebar_start = app.find('\nfunction Sidebar', app_start)
scope = app[app_start:sidebar_start]

if "window.addEventListener('sentinel-open-alert-detail'" not in scope:
    anchor = '  const refresh=()=>setRefreshKey(x=>x+1)'
    listener = """
  useEffect(()=>{
    const detailHandler=e=>openSecurityAlertDetail(e.detail)
    const soarHandler=e=>openSecurityAlertSoar(e.detail)
    window.addEventListener('sentinel-open-alert-detail',detailHandler)
    window.addEventListener('sentinel-open-alert-soar',soarHandler)
    return()=>{
      window.removeEventListener('sentinel-open-alert-detail',detailHandler)
      window.removeEventListener('sentinel-open-alert-soar',soarHandler)
    }
  },[incidents])
"""
    app = insert_after(app, anchor, listener, 'App refresh')

# ------------------------------------------------------------------
# 2) OverviewV2: persistent acknowledgement + custom events.
# ------------------------------------------------------------------
s, e = component_bounds(app, 'OverviewV2')
comp = app[s:e]

# remove reset effect that causes acknowledged event to reappear
comp = re.sub(
    r"\n\s*useEffect\(\(\)=>\{if\(latestRiskAlertIdV2\)setOverviewV2AckEventId\(''\)\},\[latestRiskAlertIdV2\]\)",
    '',
    comp,
)

if 'sentinel_acknowledged_security_events_v2' not in comp:
    anchor = "  const latestRiskAlertIdV2=String(latestRiskEventForAlertV2?.id??latestRiskEventForAlertV2?.event_id??'')"
    extra = """
  const ALERT_ACK_KEY='sentinel_acknowledged_security_events_v2'

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
    acknowledgeCurrentAlert()
    window.dispatchEvent(new CustomEvent('sentinel-open-alert-detail',{detail:latestRiskEventForAlertV2}))
  }

  const openCurrentAlertSoar=()=>{
    acknowledgeCurrentAlert()
    window.dispatchEvent(new CustomEvent('sentinel-open-alert-soar',{detail:latestRiskEventForAlertV2}))
  }
"""
    comp = insert_after(comp, anchor, extra, 'OverviewV2 latestRiskAlertIdV2')

comp = comp.replace(
    'latestRiskEventForAlertV2&&latestRiskAlertIdV2!==overviewV2AckEventId&&(',
    'latestRiskEventForAlertV2&&!isAlertAcknowledged&&latestRiskAlertIdV2!==overviewV2AckEventId&&(',
    1,
)
comp = comp.replace("onClick={()=>setPage('events')}", 'onClick={openCurrentAlertDetail}', 1)
comp = comp.replace(
    'onClick={()=>setOverviewV2AckEventId(latestRiskAlertIdV2)}',
    'onClick={acknowledgeCurrentAlert}',
    1,
)

if 'SOAR 즉시 대응' not in comp:
    markers = [
        '<button className="btn ghost" onClick={acknowledgeCurrentAlert}>{\'\\uD655\\uC778\'}</button>',
        '<button className="btn ghost" onClick={acknowledgeCurrentAlert}>확인</button>',
    ]
    inserted = False
    for marker in markers:
        if marker in comp:
            comp = comp.replace(
                marker,
                '<button className="btn primary" onClick={openCurrentAlertSoar}>SOAR 즉시 대응</button>' + marker,
                1,
            )
            inserted = True
            break
    if not inserted:
        raise RuntimeError('OverviewV2 confirm button not found')

app = app[:s] + comp + app[e:]

# ------------------------------------------------------------------
# 3) EventsPage reads focused event from sessionStorage.
# ------------------------------------------------------------------
s, e = component_bounds(app, 'EventsPage')
comp = app[s:e]

if "sessionStorage.getItem('sentinel_focus_event_id')" not in comp:
    anchor = "  useEffect(()=>{if(!selectedBehavior&&behaviorEvents[0])setSelectedBehavior(String(behaviorEvents[0].id));if(!selectedExplain&&explainables[0])setSelectedExplain(String(explainables[0].id))},[filtered.length])"
    effect = """
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
    comp = insert_after(comp, anchor, effect, 'EventsPage useEffect')

app = app[:s] + comp + app[e:]

# ------------------------------------------------------------------
# 4) IncidentsPage reads focused incident/event from sessionStorage.
# ------------------------------------------------------------------
s, e = component_bounds(app, 'IncidentsPage')
comp = app[s:e]

if "sessionStorage.getItem('sentinel_focus_incident_id')" not in comp:
    anchor = '  const filtered=incidents.filter'
    idx = comp.find(anchor)
    if idx < 0:
        raise RuntimeError('IncidentsPage filtered anchor not found')
    effect = """  useEffect(()=>{
    const focusIncident=sessionStorage.getItem('sentinel_focus_incident_id')
    if(focusIncident)setId(String(focusIncident))
  },[])

"""
    comp = comp[:idx] + effect + comp[idx:]

old = 'if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))'
if old in comp and 'sentinel_focus_event_id' not in comp:
    new = "const focusEvent=sessionStorage.getItem('sentinel_focus_event_id');const focused=focusEvent&&ev.find(x=>String(x.id||x.event_id)===String(focusEvent));if(focused)setSelectedEvent(String(focused.id||focused.event_id));else if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))"
    comp = comp.replace(old, new, 1)

app = app[:s] + comp + app[e:]

# ------------------------------------------------------------------
# 5) SOAR reads context from sessionStorage. No signature changes.
# ------------------------------------------------------------------
s, e = component_bounds(app, 'SoarControlPage')
comp = app[s:e]

if "sentinel_soar_event_context" not in comp:
    first_nl = comp.find('\n')
    if first_nl < 0:
        raise RuntimeError('SoarControlPage body start not found')
    state = """  const[alertContext]=useState(()=>{
    try{
      return JSON.parse(sessionStorage.getItem('sentinel_soar_event_context')||'null')
    }catch{
      return null
    }
  })
"""
    comp = comp[:first_nl+1] + state + comp[first_nl+1:]

if 'queueDlpProcessTerminate' not in comp:
    anchor = '  const call=async(path,options={})=>{'
    queue = """
  const queueDlpProcessTerminate=async()=>{
    if(!alertContext||busy)return

    const process=String(alertContext.process_name||'').toLowerCase()
    const allowed=['chrome.exe','msedge.exe','firefox.exe','brave.exe','opera.exe','outlook.exe','olk.exe','thunderbird.exe']

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
"""
    comp = insert_after(comp, anchor, queue, 'SoarControlPage call')

if 'DLP_ALERT_CONTEXT' not in comp:
    ret = re.search(r'return\s*\(\s*<>', comp)
    if not ret:
        raise RuntimeError('SoarControlPage return fragment not found')
    card = """
    {alertContext&&<Notice type="warning">
      <b>DLP_ALERT_CONTEXT · Event #{alertContext.id??alertContext.event_id??'-'}</b>
      <br/>
      {alertContext.user||'-'} · {koEvent(alertContext.event_type)} · Risk {num(alertContext.risk_score).toFixed(2)} · {alertContext.process_name||'-'}
      <div className="alert-actions">
        <button className="btn danger" disabled={Boolean(busy)} onClick={queueDlpProcessTerminate}>
          {busy==='dlp-process-terminate'?'제어 요청 중...':'탐지 프로세스 즉시 종료'}
        </button>
      </div>
    </Notice>}
"""
    comp = comp[:ret.end()] + card + comp[ret.end():]

app = app[:s] + comp + app[e:]

# ------------------------------------------------------------------
# 6) Backend allows PROCESS_TERMINATE.
# ------------------------------------------------------------------
engine = engine.replace(
    'VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT"}',
    'VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT", "PROCESS_TERMINATE"}'
)

# ------------------------------------------------------------------
# 7) Verify by feature markers only.
# ------------------------------------------------------------------
checks = {
    'ack storage': 'sentinel_acknowledged_security_events_v2' in app,
    'detail event': "sentinel-open-alert-detail" in app,
    'soar event': "sentinel-open-alert-soar" in app,
    'events focus': "sessionStorage.getItem('sentinel_focus_event_id')" in app,
    'incident focus': "sessionStorage.getItem('sentinel_focus_incident_id')" in app,
    'soar context': 'sentinel_soar_event_context' in app,
    'soar queue': 'queueDlpProcessTerminate' in app,
    'backend action': 'PROCESS_TERMINATE' in engine,
}
failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise RuntimeError('VERIFY FAILED: ' + ', '.join(failed))

APP.write_text(app, encoding='utf-8')
ENGINE.write_text(engine, encoding='utf-8')
py_compile.compile(str(ENGINE), doraise=True)

print('[VERIFY OK] persistent alert acknowledge')
print('[VERIFY OK] event/incident drilldown')
print('[VERIFY OK] SOAR event context')
print('[VERIFY OK] PROCESS_TERMINATE backend support')
print('[COMPILE OK] server/response_control_engine.py')
print('[WRITE] sentinel-react-frontend/src/App.jsx')
print('[WRITE] server/response_control_engine.py')
