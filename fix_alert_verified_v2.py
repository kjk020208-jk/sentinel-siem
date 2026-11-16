from pathlib import Path
import re, shutil, sys

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'

if not APP.exists():
    print('[ERROR] App.jsx not found:', APP)
    sys.exit(1)

backup = APP.with_name(APP.name + '.before_verified_alert_v2')
if not backup.exists():
    shutil.copy2(APP, backup)
    print('[BACKUP]', backup.relative_to(ROOT))

app = APP.read_text(encoding='utf-8')
original = app

# 1) Hide overview PageHeader
if "if(page==='overview')return null" not in app:
    old = 'function PageHeader({page}){const[t,s]=PAGE_META[page];const[now,setNow]=useState(new Date());useEffect(()=>{const id=setInterval(()=>setNow(new Date()),1000);return()=>clearInterval(id)},[]);return '
    if old not in app:
        raise RuntimeError('PageHeader anchor not found')
    app = app.replace(old, old[:-7] + "if(page==='overview')return null;return ", 1)
    print('[PATCH] overview header hidden')
else:
    print('[OK] overview header already hidden')

# 2) DLP labels
if "web_upload:'웹 업로드 시도'" not in app:
    marker = "document_analysis:'문서 분석'"
    if marker not in app:
        raise RuntimeError('koEvent marker not found')
    app = app.replace(marker, marker + ",web_upload:'웹 업로드 시도',email_send:'이메일 전송 시도',external_transfer:'외부 전송 시도'", 1)
    print('[PATCH] DLP labels added')

# 3) Find overview component flexibly
m = re.search(r'function\s+(OverviewV2|Overview)\s*\([^)]*\)\s*\{', app)
if not m:
    raise RuntimeError('OverviewV2/Overview function not found')

name = m.group(1)
start = m.start()
m2 = re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(', app[m.end():])
end = m.end() + m2.start() if m2 else len(app)
component = app[start:end]
print('[FOUND]', name)

# 4) Add dismiss state
if 'overviewAckEventId' not in component:
    brace = component.find('{')
    component = component[:brace+1] + "\n  const[overviewAckEventId,setOverviewAckEventId]=useState('')" + component[brace+1:]
    print('[PATCH] alert state added')

# 5) Add latest risky event logic
if 'const latestRiskEventForAlert=' not in component:
    lm = re.search(r'\n\s*const\s+latest\s*=\s*events\[0\]', component)
    if lm:
        ip = lm.end()
    else:
        rm = re.search(r'\n\s*return\s*', component)
        if not rm:
            raise RuntimeError('No insert point in overview')
        ip = rm.start()
    logic = (
        "\n  const latestRiskEventForAlert=events.find(e=>['HIGH','CRITICAL'].includes(String(e.risk_level||'').toUpperCase()))||null"
        "\n  const latestRiskAlertId=String(latestRiskEventForAlert?.id??latestRiskEventForAlert?.event_id??'')"
        "\n  useEffect(()=>{if(latestRiskAlertId)setOverviewAckEventId('')},[latestRiskAlertId])\n"
    )
    component = component[:ip] + logic + component[ip:]
    print('[PATCH] latest risk logic added')

# 6) Insert alert UI immediately after first return fragment/div
if 'overview-live-critical-alert' not in component:
    anchors = ['return (\n    <>', 'return(\n    <>', 'return <>', 'return<>']
    ip = -1
    for a in anchors:
        p = component.find(a)
        if p >= 0:
            ip = p + len(a)
            break
    if ip < 0:
        rm = re.search(r'return\s*\(\s*', component)
        if rm:
            ip = rm.end()
        else:
            raise RuntimeError('Overview return block not found')

    alert = '''
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
            사용자 {latestRiskEventForAlert.user||'-'} · {koEvent(latestRiskEventForAlert.event_type)} · Risk {num(latestRiskEventForAlert.risk_score).toFixed(2)} · Event #{latestRiskEventForAlert.id||latestRiskEventForAlert.event_id}
            {latestRiskEventForAlert.file_name&&<> · 파일 {latestRiskEventForAlert.file_name}</>}
            {latestRiskEventForAlert.process_name&&<> · 프로세스 {latestRiskEventForAlert.process_name}</>}
          </div>
          <div className="alert-actions">
            <button className="btn danger" onClick={()=>setPage('events')}>이벤트 상세 확인</button>
            <button className="btn ghost" onClick={()=>setOverviewAckEventId(latestRiskAlertId)}>확인</button>
          </div>
        </div>
      )}
'''
    component = component[:ip] + alert + component[ip:]
    print('[PATCH] alert UI inserted')

app = app[:start] + component + app[end:]

# 7) Verify
required = ["if(page==='overview')return null", 'overviewAckEventId', 'latestRiskEventForAlert', 'overview-live-critical-alert']
missing = [x for x in required if x not in app]
if missing:
    raise RuntimeError('VERIFY FAILED: ' + ', '.join(missing))
if app == original:
    raise RuntimeError('VERIFY FAILED: no changes made')

APP.write_text(app, encoding='utf-8')
print('[VERIFY OK] changes are really in App.jsx')
print('[WRITE]', APP.relative_to(ROOT))