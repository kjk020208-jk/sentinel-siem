
from pathlib import Path
import re, shutil, py_compile, sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
ENGINE = ROOT / "server" / "response_control_engine.py"

for p in (APP, ENGINE):
    if not p.exists():
        raise SystemExit(f"[ERROR] missing: {p}")
    b = p.with_name(p.name + ".before_alert_flow_v2")
    if not b.exists():
        shutil.copy2(p, b)

app = APP.read_text(encoding="utf-8")
engine = ENGINE.read_text(encoding="utf-8")

# 1) App state
app_start = app.find("export default function App(){")
sidebar_start = app.find("\nfunction Sidebar", app_start)
if app_start < 0 or sidebar_start < 0:
    raise RuntimeError("App scope not found")

scope = app[app_start:sidebar_start]
state_anchor = "  const [page,setPage]=useState('overview'),[autoRefresh,setAutoRefresh]=useState(true),[refreshKey,setRefreshKey]=useState(0)"
if "selectedAlertEventId" not in scope:
    if state_anchor not in app:
        raise RuntimeError("App state anchor not found")
    app = app.replace(
        state_anchor,
        state_anchor
        + "\n  const[selectedAlertEventId,setSelectedAlertEventId]=useState('')"
        + "\n  const[selectedAlertIncidentId,setSelectedAlertIncidentId]=useState('')"
        + "\n  const[soarAlertContext,setSoarAlertContext]=useState(null)",
        1,
    )

# 2) App helpers
app_start = app.find("export default function App(){")
sidebar_start = app.find("\nfunction Sidebar", app_start)
scope = app[app_start:sidebar_start]

if "const openAlertDetail=" not in scope:
    anchor = "  const latestIncident=criticalOpen[0]||incidents[0]"
    pos = app.find(anchor, app_start, sidebar_start)
    if pos < 0:
        raise RuntimeError("latestIncident anchor not found")
    pos += len(anchor)
    helper = "\n".join([
        "",
        "  const incidentForAlertEvent=eventId=>{",
        "    const target=String(eventId||'')",
        "    if(!target)return null",
        "    return incidents.find(i=>{",
        "      const ids=[]",
        "      if(Array.isArray(i.event_ids))ids.push(...i.event_ids)",
        "      if(Array.isArray(i.related_event_ids))ids.push(...i.related_event_ids)",
        "      const story=Array.isArray(i.storyline)?i.storyline:[]",
        "      story.forEach(s=>ids.push(s?.event_id??s?.id))",
        "      return ids.some(x=>String(x)===target)",
        "    })||null",
        "  }",
        "",
        "  const openAlertDetail=event=>{",
        "    const eventId=String(event?.id??event?.event_id??'')",
        "    if(!eventId)return",
        "    setSelectedAlertEventId(eventId)",
        "    const incident=incidentForAlertEvent(eventId)",
        "    if(incident){",
        "      setSelectedAlertIncidentId(String(incident.id??incident.incident_id??''))",
        "      setPage('incidents')",
        "    }else{",
        "      setSelectedAlertIncidentId('')",
        "      setPage('events')",
        "    }",
        "  }",
        "",
        "  const openAlertSoar=event=>{",
        "    setSoarAlertContext(event||null)",
        "    setPage('soar')",
        "  }",
        "",
    ])
    app = app[:pos] + helper + app[pos:]

# 3) Render props - robust regex
app, n1 = re.subn(
    r"<OverviewV2\b([^>]*)/>",
    lambda m: (
        m.group(0)
        if "onAlertDetail=" in m.group(0)
        else m.group(0)[:-2] + " onAlertDetail={openAlertDetail} onAlertSoar={openAlertSoar}/>"
    ),
    app,
    count=1,
)

app, n2 = re.subn(
    r"<EventsPage\b([^>]*)/>",
    lambda m: (
        m.group(0)
        if "initialEventId=" in m.group(0)
        else "<EventsPage key={`events-${selectedAlertEventId}`} events={events} initialEventId={selectedAlertEventId}/>"
    ),
    app,
    count=1,
)

app, n3 = re.subn(
    r"<IncidentsPage\b([^>]*)/>",
    lambda m: (
        m.group(0)
        if "initialEventId=" in m.group(0)
        else "<IncidentsPage key={`inc-${selectedAlertIncidentId}-${selectedAlertEventId}`} incidents={incidents} allEvents={events} initialId={selectedAlertIncidentId||latestIncident?.id} initialEventId={selectedAlertEventId}/>"
    ),
    app,
    count=1,
)

app = app.replace(
    "{page==='soar'&&<SoarControlPage/>}",
    "{page==='soar'&&<SoarControlPage context={soarAlertContext}/>} ",
    1,
)

# 4) OverviewV2 persistent ack + buttons
app = app.replace(
    "function OverviewV2({events,users,latestIncident,setPage,error,latency}){",
    "function OverviewV2({events,users,latestIncident,setPage,error,latency,onAlertDetail,onAlertSoar}){",
    1,
)

m = re.search(r"function\s+OverviewV2\s*\([^)]*\)\s*\{", app)
if not m:
    raise RuntimeError("OverviewV2 not found")
nxt = re.search(r"\nfunction\s+[A-Za-z0-9_]+\s*\(", app[m.end():])
end = m.end() + nxt.start() if nxt else len(app)
comp = app[m.start():end]

comp = re.sub(
    r"\n\s*useEffect\(\(\)=>\{if\(latestRiskAlertIdV2\)setOverviewV2AckEventId\(''\)\},\[latestRiskAlertIdV2\]\)",
    "",
    comp,
)

if "sentinel_acknowledged_security_events_v1" not in comp:
    anchor = "  const latestRiskAlertIdV2=String(latestRiskEventForAlertV2?.id??latestRiskEventForAlertV2?.event_id??'')"
    p = comp.find(anchor)
    if p < 0:
        raise RuntimeError("latestRiskAlertIdV2 anchor not found")
    p += len(anchor)

    extra = "\n".join([
        "",
        "  const ALERT_ACK_KEY='sentinel_acknowledged_security_events_v1'",
        "  const isAlertAcknowledged=(()=>{",
        "    try{",
        "      const ids=JSON.parse(localStorage.getItem(ALERT_ACK_KEY)||'[]')",
        "      return Array.isArray(ids)&&ids.map(String).includes(latestRiskAlertIdV2)",
        "    }catch{return false}",
        "  })()",
        "  const acknowledgeCurrentAlert=()=>{",
        "    try{",
        "      const current=JSON.parse(localStorage.getItem(ALERT_ACK_KEY)||'[]')",
        "      const ids=Array.isArray(current)?current.map(String):[]",
        "      if(!ids.includes(latestRiskAlertIdV2))ids.push(latestRiskAlertIdV2)",
        "      localStorage.setItem(ALERT_ACK_KEY,JSON.stringify(ids.slice(-200)))",
        "    }catch{}",
        "    setOverviewV2AckEventId(latestRiskAlertIdV2)",
        "  }",
        "  const openAlertDetailAndAck=()=>{acknowledgeCurrentAlert();onAlertDetail?.(latestRiskEventForAlertV2)}",
        "  const openAlertSoarAndAck=()=>{acknowledgeCurrentAlert();onAlertSoar?.(latestRiskEventForAlertV2)}",
        "",
    ])
    comp = comp[:p] + extra + comp[p:]

comp = comp.replace(
    "latestRiskEventForAlertV2&&latestRiskAlertIdV2!==overviewV2AckEventId&&(",
    "latestRiskEventForAlertV2&&!isAlertAcknowledged&&latestRiskAlertIdV2!==overviewV2AckEventId&&(",
    1,
)
comp = comp.replace("onClick={()=>setPage('events')}", "onClick={openAlertDetailAndAck}", 1)
comp = comp.replace("onClick={()=>setOverviewV2AckEventId(latestRiskAlertIdV2)}", "onClick={acknowledgeCurrentAlert}", 1)

if "openAlertSoarAndAck" in comp and "SOAR 즉시 대응" not in comp:
    marker = "<button className=\"btn ghost\" onClick={acknowledgeCurrentAlert}>{'\\uD655\\uC778'}</button>"
    if marker in comp:
        comp = comp.replace(
            marker,
            "<button className=\"btn primary\" onClick={openAlertSoarAndAck}>SOAR 즉시 대응</button>" + marker,
            1,
        )

app = app[:m.start()] + comp + app[end:]

# 5) EventsPage deep-link
app = app.replace("function EventsPage({events}){", "function EventsPage({events,initialEventId}){", 1)
m = re.search(r"function\s+EventsPage\s*\([^)]*\)\s*\{", app)
if not m:
    raise RuntimeError("EventsPage not found")
nxt = re.search(r"\nfunction\s+[A-Za-z0-9_]+\s*\(", app[m.end():])
end = m.end() + nxt.start() if nxt else len(app)
comp = app[m.start():end]

if "initialEventId&&events.find" not in comp:
    anchor = "  useEffect(()=>{if(!selectedBehavior&&behaviorEvents[0])setSelectedBehavior(String(behaviorEvents[0].id));if(!selectedExplain&&explainables[0])setSelectedExplain(String(explainables[0].id))},[filtered.length])"
    p = comp.find(anchor)
    if p < 0:
        raise RuntimeError("EventsPage effect anchor not found")
    p += len(anchor)

    code = "\n".join([
        "",
        "  useEffect(()=>{",
        "    if(!initialEventId)return",
        "    const target=events.find(e=>String(e.id??e.event_id)===String(initialEventId))",
        "    if(!target)return",
        "    setLevel('전체');setUser('전체');setType('전체');setSearch('')",
        "    setSelectedExplain(String(initialEventId))",
        "    setExplanation(null);setEventAI(null);setExErr('')",
        "    api.riskExplanation(initialEventId).then(setExplanation).catch(e=>setExErr(e.message))",
        "  },[initialEventId])",
        "",
    ])
    comp = comp[:p] + code + comp[p:]

app = app[:m.start()] + comp + app[end:]

# 6) IncidentsPage deep-link
app = app.replace(
    "function IncidentsPage({incidents,allEvents=[],initialId}){",
    "function IncidentsPage({incidents,allEvents=[],initialId,initialEventId}){",
    1,
)

m = re.search(r"function\s+IncidentsPage\s*\([^)]*\)\s*\{", app)
if not m:
    raise RuntimeError("IncidentsPage not found")
nxt = re.search(r"\nfunction\s+[A-Za-z0-9_]+\s*\(", app[m.end():])
end = m.end() + nxt.start() if nxt else len(app)
comp = app[m.start():end]

if "if(initialId)setId(String(initialId))" not in comp:
    anchor = "  const filtered=incidents.filter(i=>(level==='전체'||String(i.severity||i.risk_level).toUpperCase()===level)&&(status==='전체'||String(i.status||'OPEN').toUpperCase()===status))"
    p = comp.find(anchor)
    if p < 0:
        raise RuntimeError("IncidentsPage filtered anchor not found")
    p += len(anchor)
    comp = comp[:p] + "\n  useEffect(()=>{if(initialId)setId(String(initialId))},[initialId])" + comp[p:]

old = "if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))"
new = "const target=initialEventId&&ev.find(x=>String(x.id||x.event_id)===String(initialEventId));if(target)setSelectedEvent(String(target.id||target.event_id));else if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))"
if old in comp:
    comp = comp.replace(old, new, 1)

app = app[:m.start()] + comp + app[end:]

# 7) SOAR context + queue
app = app.replace("function SoarControlPage(){", "function SoarControlPage({context}){", 1)
m = re.search(r"function\s+SoarControlPage\s*\([^)]*\)\s*\{", app)
if m:
    nxt = re.search(r"\nfunction\s+[A-Za-z0-9_]+\s*\(", app[m.end():])
    end = m.end() + nxt.start() if nxt else len(app)
    comp = app[m.start():end]

    if "queueDlpProcessTerminate" not in comp:
        anchor = "  const call=async(path,options={})=>{"
        p = comp.find(anchor)
        if p < 0:
            raise RuntimeError("Soar call anchor not found")

        code = "\n".join([
            "  const queueDlpProcessTerminate=async()=>{",
            "    if(!context||busy)return",
            "    const process=String(context.process_name||'').toLowerCase()",
            "    const allowed=['chrome.exe','msedge.exe','firefox.exe','brave.exe','opera.exe','outlook.exe','olk.exe','thunderbird.exe']",
            "    if(!allowed.includes(process)){setErr(`실제 종료 지원 대상 프로세스가 아닙니다: ${process||'-'}`);return}",
            "    setBusy('dlp-process-terminate');setMsg('');setErr('')",
            "    try{",
            "      const result=await call('/response-controls',{method:'POST',body:JSON.stringify({",
            "        user:context.user||'siem_demo',action_type:'PROCESS_TERMINATE',operation:'APPLY',",
            "        reason:`DLP_WEB_UPLOAD_BLOCK process=${process} event_id=${context.id??context.event_id??''}`,",
            "        risk_score:Math.round(num(context.risk_score)),requested_by:'DLP_ALERT_ADMIN'",
            "      })})",
            "      setMsg(`실제 프로세스 종료 제어가 Agent 큐에 등록되었습니다. Action #${result?.action?.id??'-'} · ${process}`)",
            "      await load()",
            "    }catch(e){setErr(e.message)}finally{setBusy('')}",
            "  }",
            "",
        ])
        comp = comp[:p] + code + comp[p:]

    app = app[:m.start()] + comp + app[end:]

# 8) Backend allow PROCESS_TERMINATE
engine = engine.replace(
    'VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT"}',
    'VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT", "PROCESS_TERMINATE"}',
)

# 9) Strong verification
checks = {
    "ack": "sentinel_acknowledged_security_events_v1" in app,
    "detail helper": "const openAlertDetail=" in app,
    "soar helper": "const openAlertSoar=" in app,
    "events render": re.search(r"<EventsPage[^>]*initialEventId=\{selectedAlertEventId\}", app) is not None,
    "incidents render": re.search(r"<IncidentsPage[^>]*initialEventId=\{selectedAlertEventId\}", app) is not None,
    "events signature": "function EventsPage({events,initialEventId}){" in app,
    "incidents signature": "function IncidentsPage({incidents,allEvents=[],initialId,initialEventId}){" in app,
    "soar context": "function SoarControlPage({context}){" in app,
    "soar queue": "queueDlpProcessTerminate" in app,
    "backend": "PROCESS_TERMINATE" in engine,
}

failed = [k for k,v in checks.items() if not v]
if failed:
    raise RuntimeError("VERIFY FAILED: " + ", ".join(failed))

APP.write_text(app, encoding="utf-8")
ENGINE.write_text(engine, encoding="utf-8")
py_compile.compile(str(ENGINE), doraise=True)

print("[VERIFY OK] persistent alert acknowledgement")
print("[VERIFY OK] event deep-link")
print("[VERIFY OK] incident/event deep-link")
print("[VERIFY OK] SOAR context + process terminate queue")
print("[COMPILE OK] server/response_control_engine.py")
print("[WRITE] sentinel-react-frontend/src/App.jsx")
print("[WRITE] server/response_control_engine.py")
