from pathlib import Path
import re, shutil, sys

ROOT=Path.cwd()
APP=ROOT/'sentinel-react-frontend'/'src'/'App.jsx'
CSS=ROOT/'sentinel-react-frontend'/'src'/'styles.css'

for p in (APP,CSS):
    if not p.exists():
        print('[ERROR] missing:',p)
        sys.exit(1)

for p in (APP,CSS):
    b=p.with_name(p.name+'.before_global_alert_v7_1')
    if not b.exists():
        shutil.copy2(p,b)
        print('[BACKUP]',b.relative_to(ROOT))

app=APP.read_text(encoding='utf-8')

# 1) App state
if 'selectedIncidentId,setSelectedIncidentId' not in app:
    pat=r"(const \[page,setPage\]=useState\('overview'\),\[autoRefresh,setAutoRefresh\]=useState\(true\),\[refreshKey,setRefreshKey\]=useState\(0\))"
    app,n=re.subn(pat, r"\1\n  const [selectedIncidentId,setSelectedIncidentId]=useState('')", app, count=1)
    if n!=1:
        raise RuntimeError('App state insertion failed')
    print('[PATCH] alert target state')

# 2) Derived event/incident logic
if 'const latestRiskEvent=' not in app:
    pat=r"(\s+const latestIncident=criticalOpen\[0\]\|\|incidents\[0\])"
    insert='''\n  const latestRiskEvent=events.find(e=>['HIGH','CRITICAL'].includes(String(e.risk_level||'').toUpperCase()))||null
  const matchingRiskIncident=latestRiskEvent
    ? incidents.filter(i=>
        String(i.user||i.username||'')===String(latestRiskEvent.user||'')
        &&String(i.status||'OPEN').toUpperCase()!=='CLOSED'
      ).sort((a,b)=>num(b.id||b.incident_id)-num(a.id||a.incident_id))[0]||null
    : null

  const openRiskAlert=()=>{
    if(matchingRiskIncident){
      setSelectedIncidentId(String(matchingRiskIncident.id||matchingRiskIncident.incident_id||''))
      setPage('incidents')
    }else{
      setPage('events')
    }
  }
'''
    app,n=re.subn(pat, lambda m:m.group(1)+insert, app, count=1)
    if n!=1:
        raise RuntimeError('latestRiskEvent insertion failed')
    print('[PATCH] latest risky event logic')

# 3) mount alert after app-shell opening
if '<GlobalSecurityAlert' not in app[app.find('export default function App()'):app.find('function Sidebar')]:
    token='return <div className="app-shell">'
    idx=app.find(token, app.find('export default function App()'))
    if idx<0:
        raise RuntimeError('app-shell return not found')
    idx += len(token)
    mount='''{latestRiskEvent&&<GlobalSecurityAlert event={latestRiskEvent} incident={matchingRiskIncident} onOpen={openRiskAlert}/>}'''
    app=app[:idx]+mount+app[idx:]
    print('[PATCH] alert mounted globally')

# 4) deep-open incident target
old="{page==='incidents'&&<IncidentsPage incidents={incidents} allEvents={events} initialId={latestIncident?.id}/>}"
if old in app:
    new="{page==='incidents'&&<IncidentsPage key={selectedIncidentId||latestIncident?.id||'incident-page'} incidents={incidents} allEvents={events} initialId={selectedIncidentId||latestIncident?.id}/>}"
    app=app.replace(old,new,1)
    print('[PATCH] incident direct open')

# 5) component
if 'function GlobalSecurityAlert(' not in app:
    anchor='function CriticalAlert({incident,onOpen}){'
    idx=app.find(anchor)
    if idx<0:
        raise RuntimeError('CriticalAlert anchor not found')
    app=app[:idx]+"function GlobalSecurityAlert({event,incident,onOpen}){\n  const eventId=event?.id??event?.event_id??''\n  const severity=String(event?.risk_level||'HIGH').toUpperCase()\n  const signature=`event:${eventId}:${severity}`\n  const storageKey='sentinel_acknowledged_risk_alerts'\n\n  const readAcked=()=>{\n    try{return new Set(JSON.parse(localStorage.getItem(storageKey)||'[]'))}\n    catch{return new Set()}\n  }\n\n  const[hidden,setHidden]=useState(()=>readAcked().has(signature))\n\n  useEffect(()=>{\n    setHidden(readAcked().has(signature))\n  },[signature])\n\n  const acknowledge=()=>{\n    const acked=readAcked()\n    acked.add(signature)\n    try{\n      localStorage.setItem(\n        storageKey,\n        JSON.stringify([...acked].slice(-200))\n      )\n    }catch{}\n    setHidden(true)\n  }\n\n  if(hidden)return null\n\n  const isDlp=['web_upload','email_send','external_transfer'].includes(\n    String(event?.event_type||'').toLowerCase()\n  )\n\n  const title=isDlp\n    ? '\ub300\uc678\ube44 \uc678\ubd80 \uc804\uc1a1 \uc2dc\ub3c4 \uac10\uc9c0'\n    : `${severity} \ubcf4\uc548 \uc774\ubca4\ud2b8 \uac10\uc9c0`\n\n  return <div className={`global-risk-alert ${severity.toLowerCase()}`}>\n    <div className=\"global-risk-alert-head\">\n      <div>\n        <span className=\"global-risk-pulse\"/>\n        <strong>{severity==='CRITICAL'?'\uae34\uae09 \ubcf4\uc548 \uc54c\ub9bc':'\uace0\uc704\ud5d8 \ubcf4\uc548 \uc54c\ub9bc'}</strong>\n      </div>\n      <span className=\"global-risk-time\">{fmt(event?.timestamp||event?.created_at)}</span>\n    </div>\n\n    <div className=\"global-risk-title\">{title}</div>\n\n    <div className=\"global-risk-summary\">\n      <span>\uc0ac\uc6a9\uc790 <b>{event?.user||'-'}</b></span>\n      <span>\uc720\ud615 <b>{koEvent(event?.event_type)}</b></span>\n      {event?.file_name&&<span>\ud30c\uc77c <b>{event.file_name}</b></span>}\n      {event?.process_name&&<span>\ud504\ub85c\uc138\uc2a4 <b>{event.process_name}</b></span>}\n      <span>\uc704\ud5d8\ub3c4 <b>{num(event?.risk_score).toFixed(2)} \u00b7 {severity}</b></span>\n    </div>\n\n    <div className=\"global-risk-actions\">\n      <button type=\"button\" className=\"btn danger\" onClick={onOpen}>\n        {incident\n          ? `\ubcf4\uc548 \uc0ac\uace0 \uc0c1\uc138 \ubcf4\uae30 \u00b7 Incident #${incident.id||incident.incident_id}`\n          : `\uc774\ubca4\ud2b8 \ubaa8\ub2c8\ud130\ub9c1\uc5d0\uc11c \ud655\uc778 \u00b7 Event #${eventId}`}\n      </button>\n      <button type=\"button\" className=\"btn ghost\" onClick={acknowledge}>\ud655\uc778</button>\n    </div>\n  </div>\n}\n\n"+app[idx:]
    print('[PATCH] alert component')

# 6) verification
scope=app[app.find('export default function App()'):app.find('function Sidebar')]
checks=[
    'const latestRiskEvent=',
    '<GlobalSecurityAlert',
    'onOpen={openRiskAlert}',
]
missing=[x for x in checks if x not in scope]
if missing:
    raise RuntimeError('Global alert mount verification failed: '+', '.join(missing))

APP.write_text(app,encoding='utf-8')
print('[VERIFY OK] GlobalSecurityAlert is mounted in App')

css=CSS.read_text(encoding='utf-8')
if '/* ===== GLOBAL SECURITY ALERT V7.1 ===== */' not in css:
    CSS.write_text(css+"\n/* ===== GLOBAL SECURITY ALERT V7.1 ===== */\n.global-risk-alert{\n  position:fixed;\n  top:18px;\n  right:22px;\n  z-index:2147483000;\n  width:min(460px,calc(100vw - 36px));\n  box-sizing:border-box;\n  padding:16px;\n  border:1px solid rgba(255,79,79,.65);\n  border-radius:13px;\n  background:linear-gradient(145deg,rgba(48,15,20,.99),rgba(15,18,24,.995));\n  box-shadow:0 20px 60px rgba(0,0,0,.58),0 0 26px rgba(255,55,65,.08);\n  animation:sentinel-alert-in .24s ease-out;\n}\n.global-risk-alert.high{\n  border-color:rgba(255,174,66,.65);\n  background:linear-gradient(145deg,rgba(45,30,10,.99),rgba(15,18,24,.995));\n}\n.global-risk-alert-head{\n  display:flex;\n  align-items:center;\n  justify-content:space-between;\n  gap:12px;\n  margin-bottom:10px;\n}\n.global-risk-alert-head>div{display:flex;align-items:center;gap:8px}\n.global-risk-alert-head strong{\n  color:#ffb6b6;\n  font-size:10px;\n  font-weight:800;\n  letter-spacing:.06em;\n}\n.global-risk-alert.high .global-risk-alert-head strong{color:#ffd19a}\n.global-risk-pulse{\n  width:8px;height:8px;flex:0 0 8px;border-radius:50%;\n  background:#ff4d4f;\n  animation:sentinel-alert-pulse 1.35s infinite;\n}\n.global-risk-alert.high .global-risk-pulse{background:#f5a623}\n.global-risk-time{color:#8994a2;font-size:9px;white-space:nowrap}\n.global-risk-title{\n  margin-bottom:11px;color:#fff;font-size:17px;font-weight:800;line-height:1.3;\n}\n.global-risk-summary{\n  display:grid;grid-template-columns:1fr 1fr;gap:8px 12px;\n  margin-bottom:14px;padding:11px 12px;\n  border:1px solid rgba(255,255,255,.07);\n  border-radius:9px;background:rgba(255,255,255,.026);\n}\n.global-risk-summary span{min-width:0;color:#8e99a8;font-size:9px;line-height:1.45}\n.global-risk-summary b{\n  display:block;margin-top:2px;overflow:hidden;color:#e8edf3;font-size:10px;\n  font-weight:650;text-overflow:ellipsis;white-space:nowrap;\n}\n.global-risk-actions{display:flex;gap:8px}\n.global-risk-actions .btn.danger{flex:1}\n.global-risk-actions .btn.ghost{flex:0 0 auto;min-width:70px}\n@keyframes sentinel-alert-in{\n  from{opacity:0;transform:translateY(-10px) scale(.985)}\n  to{opacity:1;transform:none}\n}\n@keyframes sentinel-alert-pulse{\n  0%{box-shadow:0 0 0 0 rgba(255,77,79,.55)}\n  70%{box-shadow:0 0 0 8px rgba(255,77,79,0)}\n  100%{box-shadow:0 0 0 0 rgba(255,77,79,0)}\n}\n@media(max-width:620px){\n  .global-risk-alert{top:10px;right:10px;left:10px;width:auto}\n  .global-risk-summary{grid-template-columns:1fr}\n  .global-risk-actions{flex-direction:column}\n}\n",encoding='utf-8')
    print('[PATCH] alert CSS')

print()
print('GLOBAL SECURITY ALERT v7.1 COMPLETE')
print('Build -> commit -> push')
