from pathlib import Path
import shutil, sys

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'

if not APP.exists():
    print('[ERROR] App.jsx not found')
    sys.exit(1)

backup = APP.with_name(APP.name + '.before_verified_alert_fix')
if not backup.exists():
    shutil.copy2(APP, backup)
    print('[BACKUP]', backup.relative_to(ROOT))

app = APP.read_text(encoding='utf-8')

# 1) Hide the big overview header
old = "function PageHeader({page}){const[t,s]=PAGE_META[page];const[now,setNow]=useState(new Date());useEffect(()=>{const id=setInterval(()=>setNow(new Date()),1000);return()=>clearInterval(id)},[]);return <div className=\"soc-header\"><div><div className=\"soc-title\">{t}</div><div className=\"soc-subtitle\">{s}</div></div><div className=\"header-right\"><div className=\"header-time\">{fmt(now)}</div></div></div>}"
new = "function PageHeader({page}){const[t,s]=PAGE_META[page];const[now,setNow]=useState(new Date());useEffect(()=>{const id=setInterval(()=>setNow(new Date()),1000);return()=>clearInterval(id)},[]);if(page==='overview')return null;return <div className=\"soc-header\"><div><div className=\"soc-title\">{t}</div><div className=\"soc-subtitle\">{s}</div></div><div className=\"header-right\"><div className=\"header-time\">{fmt(now)}</div></div></div>}"
if old not in app and "if(page==='overview')return null" not in app:
    raise RuntimeError('PageHeader exact match failed')
if old in app:
    app = app.replace(old, new, 1)
    print('[PATCH] overview header hidden')

# 2) DLP labels
if "web_upload:'웹 업로드 시도'" not in app:
    marker = "document_analysis:'문서 분석'"
    if marker not in app:
        raise RuntimeError('koEvent marker not found')
    app = app.replace(marker, marker + ",web_upload:'웹 업로드 시도',email_send:'이메일 전송 시도',external_transfer:'외부 전송 시도'", 1)
    print('[PATCH] DLP labels added')

# 3) OverviewV2 state
sig = 'function OverviewV2({events,users,latestIncident,setPage,error,latency}){'
start = app.find(sig)
if start < 0:
    raise RuntimeError('OverviewV2 not found')

insert_pos = start + len(sig)
if 'overviewAckEventId' not in app[start:start+500]:
    app = app[:insert_pos] + "\n  const[overviewAckEventId,setOverviewAckEventId]=useState('')" + app[insert_pos:]
    print('[PATCH] alert ack state added')

# 4) Add latest risky event logic after const latest=events[0]
start = app.find(sig)
anchor = '  const latest=events[0]'
pos = app.find(anchor, start)
if pos < 0:
    raise RuntimeError('latest event anchor not found')
pos += len(anchor)

if 'const latestRiskEventForAlert=' not in app[start:start+4000]:
    logic = """

  const latestRiskEventForAlert=events.find(e=>
    ['HIGH','CRITICAL'].includes(
      String(e.risk_level||'').toUpperCase()
    )
  )||null

  const latestRiskAlertId=String(
    latestRiskEventForAlert?.id??
    latestRiskEventForAlert?.event_id??
    ''
  )

  useEffect(()=>{
    if(latestRiskAlertId){
      setOverviewAckEventId('')
    }
  },[latestRiskAlertId])
"""
    app = app[:pos] + logic + app[pos:]
    print('[PATCH] latest risk event logic added')

# 5) Insert alert before overview-v2 content
start = app.find(sig)
return_anchor = '  return (\n    <>'
pos = app.find(return_anchor, start)
if pos < 0:
    raise RuntimeError('OverviewV2 return anchor not found')
pos += len(return_anchor)

if 'overview-live-critical-alert' not in app[start:start+12000]:
    alert = """

      {latestRiskEventForAlert&&latestRiskAlertId!==overviewAckEventId&&(
        <div className="critical-alert overview-live-critical-alert">
          <div className="live-alert-top">
            <div className="live-alert-title">● LIVE SECURITY ALERT</div>
            <div className="live-alert-time">{fmt(latestRiskEventForAlert.timestamp||latestRiskEventForAlert.created_at)}</div>
          </div>

          <div className="live-alert-main">
            {['web_upload','email_send','external_transfer'].includes(String(latestRiskEventForAlert.event_type||'').toLowerCase())
              ? '대외비 외부 전송 시도 감지'
              : `${String(latestRiskEventForAlert.risk_level||'HIGH').toUpperCase()} 보안 이벤트 감지`}
          </div>

          <div className="live-alert-meta">
            사용자 {latestRiskEventForAlert.user||'-'} · 
            {koEvent(latestRiskEventForAlert.event_type)} · 
            Risk {num(latestRiskEventForAlert.risk_score).toFixed(2)} · 
            Event #{latestRiskEventForAlert.id||latestRiskEventForAlert.event_id}
            {latestRiskEventForAlert.file_name&&<> · 파일 {latestRiskEventForAlert.file_name}</>}
            {latestRiskEventForAlert.process_name&&<> · 프로세스 {latestRiskEventForAlert.process_name}</>}
          </div>

          <div className="alert-actions">
            <button className="btn danger" onClick={()=>setPage('events')}>
              이벤트 상세 확인
            </button>
            <button className="btn ghost" onClick={()=>setOverviewAckEventId(latestRiskAlertId)}>
              확인
            </button>
          </div>
        </div>
      )}
"""
    app = app[:pos] + alert + app[pos:]
    print('[PATCH] live alert inserted into OverviewV2')

# 6) hard verification before writing
required = [
    "if(page==='overview')return null",
    'overviewAckEventId',
    'const latestRiskEventForAlert=',
    'overview-live-critical-alert',
    '대외비 외부 전송 시도 감지',
]
missing = [x for x in required if x not in app]
if missing:
    raise RuntimeError('VERIFY FAILED: ' + ', '.join(missing))

APP.write_text(app, encoding='utf-8')
print('[VERIFY OK] all required code is in App.jsx')
print('[WRITE]', APP.relative_to(ROOT))