from pathlib import Path
import re, shutil, sys

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'
CSS = ROOT / 'sentinel-react-frontend' / 'src' / 'styles.css'

for p in (APP, CSS):
    if not p.exists():
        print('[ERROR] missing:', p)
        sys.exit(1)

for p in (APP, CSS):
    b = p.with_name(p.name + '.before_alert_v8')
    if not b.exists():
        shutil.copy2(p, b)
        print('[BACKUP]', b.relative_to(ROOT))

app = APP.read_text(encoding='utf-8')

app_start = app.find('export default function App(){')
sidebar_start = app.find('function Sidebar', app_start)
if app_start < 0 or sidebar_start < 0:
    raise RuntimeError('App component scope not found')

scope = app[app_start:sidebar_start]

# 1) Current alert dismiss state
if 'alertDismissedId,setAlertDismissedId' not in scope:
    pat = r"(const \[page,setPage\]=useState\('overview'\),\[autoRefresh,setAutoRefresh\]=useState\(true\),\[refreshKey,setRefreshKey\]=useState\(0\))"
    app, n = re.subn(
        pat,
        r"\1\n  const [alertDismissedId,setAlertDismissedId]=useState('')",
        app,
        count=1,
    )
    if n != 1:
        raise RuntimeError('alert dismiss state insertion failed')
    print('[PATCH] alert dismiss state')

# 2) Simplified newest HIGH/CRITICAL event logic
app_start = app.find('export default function App(){')
sidebar_start = app.find('function Sidebar', app_start)
scope = app[app_start:sidebar_start]

if 'const newestRiskEvent=' not in scope:
    anchor = '  const latestIncident=criticalOpen[0]||incidents[0]'
    idx = app.find(anchor, app_start, sidebar_start)
    if idx < 0:
        raise RuntimeError('latestIncident anchor not found')
    idx += len(anchor)

    logic = r'''
  const newestRiskEvent=events.find(e=>
    ['HIGH','CRITICAL'].includes(
      String(e.risk_level||'').toUpperCase()
    )
  )||null

  const newestRiskEventId=String(
    newestRiskEvent?.id??newestRiskEvent?.event_id??''
  )

  useEffect(()=>{
    if(newestRiskEventId){
      setAlertDismissedId('')
    }
  },[newestRiskEventId])

  const showGlobalRiskAlert=Boolean(
    newestRiskEvent &&
    newestRiskEventId &&
    alertDismissedId!==newestRiskEventId
  )
'''
    app = app[:idx] + logic + app[idx:]
    print('[PATCH] newest risk event logic')

# 3) Remove previously mounted GlobalSecurityAlert if any
app_start = app.find('export default function App(){')
sidebar_start = app.find('function Sidebar', app_start)
scope = app[app_start:sidebar_start]
scope = re.sub(r"\{latestRiskEvent&&\s*\(\s*<GlobalSecurityAlert[\s\S]*?/>\s*\)\}", '', scope, count=1)
scope = re.sub(r"\{latestRiskEvent&&<GlobalSecurityAlert[\s\S]*?/>\}", '', scope, count=1)
app = app[:app_start] + scope + app[sidebar_start:]

# 4) Inline alert directly in App root
app_start = app.find('export default function App(){')
sidebar_start = app.find('function Sidebar', app_start)
scope = app[app_start:sidebar_start]

if 'simple-global-alert-v8' not in scope:
    token = 'return <div className="app-shell">'
    idx = app.find(token, app_start, sidebar_start)
    if idx < 0:
        raise RuntimeError('app-shell return not found')
    idx += len(token)

    mount = r'''{showGlobalRiskAlert&&<div className={`global-risk-alert simple-global-alert-v8 ${String(newestRiskEvent.risk_level||'HIGH').toLowerCase()}`}>
      <div className="global-risk-alert-head">
        <div>
          <span className="global-risk-pulse"/>
          <strong>{String(newestRiskEvent.risk_level||'').toUpperCase()==='CRITICAL'?'긴급 보안 알림':'고위험 보안 알림'}</strong>
        </div>
        <span className="global-risk-time">{fmt(newestRiskEvent.timestamp||newestRiskEvent.created_at)}</span>
      </div>
      <div className="global-risk-title">
        {['web_upload','email_send','external_transfer'].includes(String(newestRiskEvent.event_type||'').toLowerCase())
          ? '대외비 외부 전송 시도 감지'
          : `${String(newestRiskEvent.risk_level||'HIGH').toUpperCase()} 보안 이벤트 감지`}
      </div>
      <div className="global-risk-summary">
        <span>사용자 <b>{newestRiskEvent.user||'-'}</b></span>
        <span>유형 <b>{koEvent(newestRiskEvent.event_type)}</b></span>
        {newestRiskEvent.file_name&&<span>파일 <b>{newestRiskEvent.file_name}</b></span>}
        {newestRiskEvent.process_name&&<span>프로세스 <b>{newestRiskEvent.process_name}</b></span>}
        <span>위험도 <b>{num(newestRiskEvent.risk_score).toFixed(2)} · {String(newestRiskEvent.risk_level||'HIGH').toUpperCase()}</b></span>
      </div>
      <div className="global-risk-actions">
        <button type="button" className="btn danger" onClick={()=>setPage('events')}>
          이벤트 모니터링에서 바로 확인 · Event #{newestRiskEvent.id||newestRiskEvent.event_id}
        </button>
        <button type="button" className="btn ghost" onClick={()=>setAlertDismissedId(newestRiskEventId)}>
          확인
        </button>
      </div>
    </div>}'''
    app = app[:idx] + mount + app[idx:]
    print('[PATCH] inline global alert mounted')

# 5) Remove big overview header only on overview page
old = '<TopBar/><div className="content"><PageHeader page={page}/>'
new = '<TopBar/><div className="content">{page!==\'overview\'&&<PageHeader page={page}/>}'
if old in app:
    app = app.replace(old, new, 1)
    print('[PATCH] overview PageHeader removed')
else:
    app, n = re.subn(
        r'<TopBar/>\s*<div className="content">\s*<PageHeader page=\{page\}/>',
        '<TopBar/><div className="content">{page!==\'overview\'&&<PageHeader page={page}/>}',
        app,
        count=1,
    )
    if n:
        print('[PATCH] overview PageHeader removed (regex)')

# 6) Ensure DLP Korean labels
if "web_upload:'웹 업로드 시도'" not in app:
    app = app.replace(
        "document_analysis:'문서 분석'",
        "document_analysis:'문서 분석',web_upload:'웹 업로드 시도',email_send:'이메일 전송 시도',external_transfer:'외부 전송 시도'",
        1,
    )

# 7) Verify
app_start = app.find('export default function App(){')
sidebar_start = app.find('function Sidebar', app_start)
scope = app[app_start:sidebar_start]
checks = [
    'const newestRiskEvent=',
    'showGlobalRiskAlert',
    'simple-global-alert-v8',
    'setAlertDismissedId(newestRiskEventId)',
    "page!=='overview'&&<PageHeader page={page}/>",
]
missing = [x for x in checks if x not in scope]
if missing:
    raise RuntimeError('VERIFY FAILED: ' + ', '.join(missing))

APP.write_text(app, encoding='utf-8')
print('[VERIFY OK] inline alert mounted')
print('[WRITE] App.jsx')

css = CSS.read_text(encoding='utf-8')
marker = '/* ===== SIMPLE GLOBAL ALERT V8 ===== */'
if marker not in css:
    css += r'''

/* ===== SIMPLE GLOBAL ALERT V8 ===== */
.simple-global-alert-v8{
  position:fixed !important;
  top:18px !important;
  right:22px !important;
  z-index:2147483640 !important;
  display:block !important;
  visibility:visible !important;
  opacity:1 !important;
  pointer-events:auto !important;
}
.simple-global-alert-v8.critical{
  border-color:rgba(255,72,76,.85) !important;
  box-shadow:0 22px 70px rgba(0,0,0,.62),0 0 30px rgba(255,55,65,.16) !important;
}
'''
    CSS.write_text(css, encoding='utf-8')
    print('[WRITE] styles.css')

print('SENTINEL Alert v8 complete')
