from pathlib import Path
import re, shutil, py_compile, sys

ROOT=Path.cwd()
APP=ROOT/'sentinel-react-frontend'/'src'/'App.jsx'
ENGINE=ROOT/'server'/'response_control_engine.py'

for p in (APP,ENGINE):
    if not p.exists():
        raise SystemExit(f'[ERROR] missing: {p}')
    b=p.with_name(p.name+'.before_alert_flow_final')
    if not b.exists(): shutil.copy2(p,b)

app=APP.read_text(encoding='utf-8')

# ---------- App-level navigation state ----------
app_start=app.find('export default function App(){')
sidebar_start=app.find('\nfunction Sidebar',app_start)
if app_start<0 or sidebar_start<0: raise RuntimeError('App scope not found')
scope=app[app_start:sidebar_start]

state_anchor="  const [page,setPage]=useState('overview'),[autoRefresh,setAutoRefresh]=useState(true),[refreshKey,setRefreshKey]=useState(0)"
if 'selectedAlertEventId' not in scope:
    if state_anchor not in app: raise RuntimeError('App state anchor not found')
    app=app.replace(state_anchor,state_anchor+"\n  const[selectedAlertEventId,setSelectedAlertEventId]=useState('')\n  const[selectedAlertIncidentId,setSelectedAlertIncidentId]=useState('')\n  const[soarAlertContext,setSoarAlertContext]=useState(null)",1)

app_start=app.find('export default function App(){'); sidebar_start=app.find('\nfunction Sidebar',app_start)
scope=app[app_start:sidebar_start]

if 'const incidentForAlertEvent=' not in scope:
    anchor='  const latestIncident=criticalOpen[0]||incidents[0]'
    pos=app.find(anchor,app_start,sidebar_start)
    if pos<0: raise RuntimeError('latestIncident anchor not found')
    pos+=len(anchor)
    helper=r'''

  const incidentForAlertEvent=eventId=>{
    const target=String(eventId||'')
    if(!target)return null
    return incidents.find(i=>{
      const ids=[]
      if(Array.isArray(i.event_ids))ids.push(...i.event_ids)
      if(Array.isArray(i.related_event_ids))ids.push(...i.related_event_ids)
      const story=Array.isArray(i.storyline)?i.storyline:[]
      story.forEach(s=>ids.push(s?.event_id??s?.id))
      return ids.some(x=>String(x)===target)
    })||null
  }

  const openAlertDetail=event=>{
    const eventId=String(event?.id??event?.event_id??'')
    if(!eventId)return
    setSelectedAlertEventId(eventId)
    const incident=incidentForAlertEvent(eventId)
    if(incident){
      setSelectedAlertIncidentId(String(incident.id??incident.incident_id??''))
      setPage('incidents')
    }else{
      setSelectedAlertIncidentId('')
      setPage('events')
    }
  }

  const openAlertSoar=event=>{
    setSoarAlertContext(event||null)
    setPage('soar')
  }
'''
    app=app[:pos]+helper+app[pos:]

# ---------- App render props ----------
app=app.replace(
    "<OverviewV2 events={events} users={users} latestIncident={latestIncident} setPage={setPage} error={eventsErr} latency={eventsLatency}/>",
    "<OverviewV2 events={events} users={users} latestIncident={latestIncident} setPage={setPage} error={eventsErr} latency={eventsLatency} onAlertDetail={openAlertDetail} onAlertSoar={openAlertSoar}/>",1)
app=app.replace(
    "<EventsPage events={events}/>",
    "<EventsPage key={`events-${selectedAlertEventId}`} events={events} initialEventId={selectedAlertEventId}/>",1)
app=app.replace(
    "<IncidentsPage incidents={incidents} allEvents={events} initialId={latestIncident?.id}/>",
    "<IncidentsPage key={`inc-${selectedAlertIncidentId}-${selectedAlertEventId}`} incidents={incidents} allEvents={events} initialId={selectedAlertIncidentId||latestIncident?.id} initialEventId={selectedAlertEventId}/>",1)
app=app.replace("{page==='soar'&&<SoarControlPage/>}","{page==='soar'&&<SoarControlPage context={soarAlertContext}/>}" ,1)

# ---------- OverviewV2 persistent acknowledgement + buttons ----------
app=app.replace(
    'function OverviewV2({events,users,latestIncident,setPage,error,latency}){',
    'function OverviewV2({events,users,latestIncident,setPage,error,latency,onAlertDetail,onAlertSoar}){',1)

m=re.search(r'function\s+OverviewV2\s*\([^)]*\)\s*\{',app)
if not m: raise RuntimeError('OverviewV2 not found')
nxt=re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(',app[m.end():])
end=m.end()+nxt.start() if nxt else len(app)
comp=app[m.start():end]

# remove reset effect that reopens same event
comp=re.sub(r"\n\s*useEffect\(\(\)=>\{if\(latestRiskAlertIdV2\)setOverviewV2AckEventId\(''\)\},\[latestRiskAlertIdV2\]\)","",comp)

if 'const ALERT_ACK_KEY=' not in comp:
    anchor="  const latestRiskAlertIdV2=String(latestRiskEventForAlertV2?.id??latestRiskEventForAlertV2?.event_id??'')"
    p=comp.find(anchor)
    if p<0: raise RuntimeError('latestRiskAlertIdV2 anchor not found')
    p+=len(anchor)
    extra=r'''
  const ALERT_ACK_KEY='sentinel_acknowledged_security_events_v1'
  const isAlertAcknowledged=(()=>{
    try{
      const ids=JSON.parse(localStorage.getItem(ALERT_ACK_KEY)||'[]')
      return Array.isArray(ids)&&ids.map(String).includes(latestRiskAlertIdV2)
    }catch{return false}
  })()
  const acknowledgeCurrentAlert=()=>{
    try{
      const current=JSON.parse(localStorage.getItem(ALERT_ACK_KEY)||'[]')
      const ids=Array.isArray(current)?current.map(String):[]
      if(!ids.includes(latestRiskAlertIdV2))ids.push(latestRiskAlertIdV2)
      localStorage.setItem(ALERT_ACK_KEY,JSON.stringify(ids.slice(-200)))
    }catch{}
    setOverviewV2AckEventId(latestRiskAlertIdV2)
  }
  const openAlertDetailAndAck=()=>{acknowledgeCurrentAlert();onAlertDetail?.(latestRiskEventForAlertV2)}
  const openAlertSoarAndAck=()=>{acknowledgeCurrentAlert();onAlertSoar?.(latestRiskEventForAlertV2)}
'''
    comp=comp[:p]+extra+comp[p:]

comp=comp.replace(
    'latestRiskEventForAlertV2&&latestRiskAlertIdV2!==overviewV2AckEventId&&(',
    'latestRiskEventForAlertV2&&!isAlertAcknowledged&&latestRiskAlertIdV2!==overviewV2AckEventId&&(',1)

comp=comp.replace("onClick={()=>setPage('events')}","onClick={openAlertDetailAndAck}",1)
comp=comp.replace("onClick={()=>setOverviewV2AckEventId(latestRiskAlertIdV2)}","onClick={acknowledgeCurrentAlert}",1)

if 'openAlertSoarAndAck' in comp and 'SOAR \uC989\uC2DC \uB300\uC751' not in comp:
    btn="<button className=\"btn primary\" onClick={openAlertSoarAndAck}>{'SOAR \\uC989\\uC2DC \\uB300\\uC751'}</button>"
    marker="<button className=\"btn ghost\" onClick={acknowledgeCurrentAlert}>{'\\uD655\\uC778'}</button>"
    if marker in comp: comp=comp.replace(marker,btn+marker,1)

app=app[:m.start()]+comp+app[end:]

# ---------- EventsPage direct-open ----------
app=app.replace('function EventsPage({events}){','function EventsPage({events,initialEventId}){',1)
m=re.search(r'function\s+EventsPage\s*\([^)]*\)\s*\{',app)
if not m: raise RuntimeError('EventsPage not found')
nxt=re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(',app[m.end():])
end=m.end()+nxt.start() if nxt else len(app)
comp=app[m.start():end]
if 'initialEventId&&events.find' not in comp:
    anchor="  useEffect(()=>{if(!selectedBehavior&&behaviorEvents[0])setSelectedBehavior(String(behaviorEvents[0].id));if(!selectedExplain&&explainables[0])setSelectedExplain(String(explainables[0].id))},[filtered.length])"
    p=comp.find(anchor)
    if p<0: raise RuntimeError('EventsPage initial effect anchor not found')
    p+=len(anchor)
    code=r'''
  useEffect(()=>{
    if(!initialEventId)return
    const target=events.find(e=>String(e.id??e.event_id)===String(initialEventId))
    if(!target)return
    setLevel('전체');setUser('전체');setType('전체');setSearch('')
    setSelectedExplain(String(initialEventId))
    setExplanation(null);setEventAI(null);setExErr('')
    api.riskExplanation(initialEventId).then(setExplanation).catch(e=>setExErr(e.message))
  },[initialEventId])
'''
    comp=comp[:p]+code+comp[p:]

if 'direct-event-context' not in comp:
    ret='  return <>'
    p=comp.find(ret)
    if p<0: raise RuntimeError('EventsPage return anchor not found')
    p+=len(ret)
    card=r'''{initialEventId&&(()=>{const e=events.find(x=>String(x.id??x.event_id)===String(initialEventId));return e?<Notice type="warning"><div id="direct-event-context"><b>{'\uC54C\uB9BC\uC5D0\uC11C \uC120\uD0DD\uB41C \uC774\uBCA4\uD2B8'} #{initialEventId}</b><br/>{e.user||'-'} {'\u00B7'} {koEvent(e.event_type)} {'\u00B7'} Risk {num(e.risk_score).toFixed(2)} {'\u00B7'} {e.file_name||e.file_path||e.process_name||'-'}</div></Notice>:null})()}'''
    comp=comp[:p]+card+comp[p:]
app=app[:m.start()]+comp+app[end:]

# ---------- IncidentsPage event deep-link ----------
app=app.replace('function IncidentsPage({incidents,allEvents=[],initialId}){','function IncidentsPage({incidents,allEvents=[],initialId,initialEventId}){',1)
m=re.search(r'function\s+IncidentsPage\s*\([^)]*\)\s*\{',app)
if not m: raise RuntimeError('IncidentsPage not found')
nxt=re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(',app[m.end():])
end=m.end()+nxt.start() if nxt else len(app)
comp=app[m.start():end]
if 'setId(String(initialId))' not in comp:
    anchor="  const filtered=incidents.filter(i=>(level==='전체'||String(i.severity||i.risk_level).toUpperCase()===level)&&(status==='전체'||String(i.status||'OPEN').toUpperCase()===status))"
    p=comp.find(anchor); p+=len(anchor)
    comp=comp[:p]+"\n  useEffect(()=>{if(initialId)setId(String(initialId))},[initialId])"+comp[p:]
comp=comp.replace(
    "if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))",
    "const target=initialEventId&&ev.find(x=>String(x.id||x.event_id)===String(initialEventId));if(target)setSelectedEvent(String(target.id||target.event_id));else if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))",1)
app=app[:m.start()]+comp+app[end:]

# ---------- SOAR context + real process terminate queue ----------
app=app.replace('function SoarControlPage(){','function SoarControlPage({context}){',1)
m=re.search(r'function\s+SoarControlPage\s*\([^)]*\)\s*\{',app)
if m:
    nxt=re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(',app[m.end():])
    end=m.end()+nxt.start() if nxt else len(app)
    comp=app[m.start():end]
    if 'queueDlpProcessTerminate' not in comp:
        anchor="  const call=async(path,options={})=>{"
        p=comp.find(anchor)
        if p<0: raise RuntimeError('Soar call anchor not found')
        code=r'''  const queueDlpProcessTerminate=async()=>{
    if(!context||busy)return
    const process=String(context.process_name||'').toLowerCase()
    const allowed=['chrome.exe','msedge.exe','firefox.exe','brave.exe','opera.exe','outlook.exe','olk.exe','thunderbird.exe']
    if(!allowed.includes(process)){setErr(`\uC2E4\uC81C \uC885\uB8CC \uC9C0\uC6D0 \uB300\uC0C1 \uD504\uB85C\uC138\uC2A4\uAC00 \uC544\uB2D9\uB2C8\uB2E4: ${process||'-'}`);return}
    setBusy('dlp-process-terminate');setMsg('');setErr('')
    try{
      const result=await call('/response-controls',{method:'POST',body:JSON.stringify({
        user:context.user||'siem_demo',action_type:'PROCESS_TERMINATE',operation:'APPLY',
        reason:`DLP_WEB_UPLOAD_BLOCK process=${process} event_id=${context.id??context.event_id??''}`,
        risk_score:Math.round(num(context.risk_score)),requested_by:'DLP_ALERT_ADMIN'
      })})
      setMsg(`\uC2E4\uC81C \uD504\uB85C\uC138\uC2A4 \uC885\uB8CC \uC81C\uC5B4\uAC00 Agent \uD050\uC5D0 \uB4F1\uB85D\uB418\uC5C8\uC2B5\uB2C8\uB2E4. Action #${result?.action?.id??'-'} · ${process}`)
      await load()
    }catch(e){setErr(e.message)}finally{setBusy('')}
  }

'''
        comp=comp[:p]+code+comp[p:]
    if 'DLP_ALERT_CONTEXT' not in comp:
        ret=re.search(r'return\s*\(\s*<>',comp)
        if ret:
            card=r'''
    {context&&<Notice type="warning"><b>DLP_ALERT_CONTEXT · Event #{context.id??context.event_id??'-'}</b><br/>{context.user||'-'} {'\u00B7'} {koEvent(context.event_type)} {'\u00B7'} Risk {num(context.risk_score).toFixed(2)} {'\u00B7'} {context.process_name||'-'}<div className="alert-actions"><button className="btn danger" disabled={Boolean(busy)} onClick={queueDlpProcessTerminate}>{busy==='dlp-process-terminate'?'\uC81C\uC5B4 \uC694\uCCAD \uC911...':'\uD0D0\uC9C0 \uD504\uB85C\uC138\uC2A4 \uC989\uC2DC \uC885\uB8CC'}</button></div></Notice>}
'''
            comp=comp[:ret.end()]+card+comp[ret.end():]
    app=app[:m.start()]+comp+app[end:]

# ---------- backend allow PROCESS_TERMINATE ----------
engine=ENGINE.read_text(encoding='utf-8')
engine=engine.replace('VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT"}','VALID_ACTION_TYPES = {"USB_WRITE_RESTRICT", "PROCESS_TERMINATE"}')
if 'PROCESS_TERMINATE' not in engine: raise RuntimeError('backend action type patch failed')

# ---------- final verification ----------
required=[
"sentinel_acknowledged_security_events_v1",
"openAlertDetail",
"initialEventId={selectedAlertEventId}",
"initialEventId={selectedAlertEventId}",
"queueDlpProcessTerminate",
"PROCESS_TERMINATE",
]
missing=[x for x in required if x not in app+engine]
if missing: raise RuntimeError('VERIFY FAILED: '+', '.join(missing))

APP.write_text(app,encoding='utf-8')
ENGINE.write_text(engine,encoding='utf-8')
py_compile.compile(str(ENGINE),doraise=True)
print('[VERIFY OK] persistent alert acknowledgement')
print('[VERIFY OK] Incident/Event deep-link flow')
print('[VERIFY OK] SOAR context + PROCESS_TERMINATE queue UI')
print('[COMPILE OK] server/response_control_engine.py')