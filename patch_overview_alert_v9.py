from pathlib import Path
import shutil, sys

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'
CSS = ROOT / 'sentinel-react-frontend' / 'src' / 'styles.css'

for p in (APP, CSS):
    if not p.exists():
        print('[ERROR] missing:', p)
        sys.exit(1)

for p in (APP, CSS):
    b = p.with_name(p.name + '.before_overview_alert_v9')
    if not b.exists():
        shutil.copy2(p, b)
        print('[BACKUP]', b.relative_to(ROOT))

app = APP.read_text(encoding='utf-8')

# 1) 보안 현황에서는 PageHeader 자체를 숨긴다.
old_page_header = "function PageHeader({page}){const[t,s]=PAGE_META[page];const[now,setNow]=useState(new Date());useEffect(()=>{const id=setInterval(()=>setNow(new Date()),1000);return()=>clearInterval(id)},[]);return <div className=\"soc-header\"><div><div className=\"soc-title\">{t}</div><div className=\"soc-subtitle\">{s}</div></div><div className=\"header-right\"><div className=\"header-time\">{fmt(now)}</div></div></div>}"
new_page_header = "function PageHeader({page}){const[t,s]=PAGE_META[page];const[now,setNow]=useState(new Date());useEffect(()=>{const id=setInterval(()=>setNow(new Date()),1000);return()=>clearInterval(id)},[]);if(page==='overview')return null;return <div className=\"soc-header\"><div><div className=\"soc-title\">{t}</div><div className=\"soc-subtitle\">{s}</div></div><div className=\"header-right\"><div className=\"header-time\">{fmt(now)}</div></div></div>}"
if old_page_header in app:
    app = app.replace(old_page_header, new_page_header, 1)
    print('[PATCH] overview PageHeader hidden')
elif "if(page==='overview')return null" in app:
    print('[SKIP] overview PageHeader already hidden')
else:
    raise RuntimeError('PageHeader exact block not found')

# 2) DLP 이벤트 한글 라벨 보장
if "web_upload:'웹 업로드 시도'" not in app:
    app = app.replace(
        "document_analysis:'문서 분석'",
        "document_analysis:'문서 분석',web_upload:'웹 업로드 시도',email_send:'이메일 전송 시도',external_transfer:'외부 전송 시도'",
        1
    )
    print('[PATCH] DLP Korean labels added')

# 3) OverviewV2 내부에 최신 고위험 이벤트 상태를 추가
start = app.find('function OverviewV2({events,users,latestIncident,setPage,error,latency}){')
if start < 0:
    raise RuntimeError('OverviewV2 not found')

end = app.find('\nfunction ', start + 20)
if end < 0:
    end = len(app)

component = app[start:end]

if 'overviewAlertDismissedId' not in component:
    insert_after = component.find('\n') + 1
    state_code = "  const[overviewAlertDismissedId,setOverviewAlertDismissedId]=useState('')\n"
    component = component[:insert_after] + state_code + component[insert_after:]
    print('[PATCH] Overview alert dismiss state added')

# latest 계산 직후에 알람 대상 계산 추가
if 'const overviewRiskEvent=' not in component:
    anchor = '  const latest=events[0]'
    pos = component.find(anchor)
    if pos < 0:
        raise RuntimeError('OverviewV2 latest anchor not found')
    pos += len(anchor)
    logic = """

  const overviewRiskEvent=events.find(e=>
    ['HIGH','CRITICAL'].includes(
      String(e.risk_level||'').toUpperCase()
    )
  )||null

  const overviewRiskEventId=String(
    overviewRiskEvent?.id??
    overviewRiskEvent?.event_id??
    ''
  )

  useEffect(()=>{
    if(overviewRiskEventId){
      setOverviewAlertDismissedId('')
    }
  },[overviewRiskEventId])

  const showOverviewRiskAlert=Boolean(
    overviewRiskEvent &&
    overviewRiskEventId &&
    overviewAlertDismissedId!==overviewRiskEventId
  )
"""
    component = component[:pos] + logic + component[pos:]
    print('[PATCH] Overview risky event logic added')

# return의 Fragment 직후에 실제 알람 삽입
if 'overview-security-alert-v9' not in component:
    return_anchor = '  return (\n    <>'
    pos = component.find(return_anchor)
    if pos < 0:
        raise RuntimeError('OverviewV2 return fragment not found')
    pos += len(return_anchor)
    alert = """

      {showOverviewRiskAlert&&(
        <div className={`global-risk-alert overview-security-alert-v9 ${String(overviewRiskEvent.risk_level||'HIGH').toLowerCase()}`}>
          <div className="global-risk-alert-head">
            <div>
              <span className="global-risk-pulse"/>
              <strong>{String(overviewRiskEvent.risk_level||'').toUpperCase()==='CRITICAL'?'긴급 보안 알림':'고위험 보안 알림'}</strong>
            </div>
            <span className="global-risk-time">{fmt(overviewRiskEvent.timestamp||overviewRiskEvent.created_at)}</span>
          </div>

          <div className="global-risk-title">
            {['web_upload','email_send','external_transfer'].includes(String(overviewRiskEvent.event_type||'').toLowerCase())
              ? '대외비 외부 전송 시도 감지'
              : `${String(overviewRiskEvent.risk_level||'HIGH').toUpperCase()} 보안 이벤트 감지`}
          </div>

          <div className="global-risk-summary">
            <span>사용자 <b>{overviewRiskEvent.user||'-'}</b></span>
            <span>유형 <b>{koEvent(overviewRiskEvent.event_type)}</b></span>
            {overviewRiskEvent.file_name&&<span>파일 <b>{overviewRiskEvent.file_name}</b></span>}
            {overviewRiskEvent.process_name&&<span>프로세스 <b>{overviewRiskEvent.process_name}</b></span>}
            <span>위험도 <b>{num(overviewRiskEvent.risk_score).toFixed(2)} · {String(overviewRiskEvent.risk_level||'HIGH').toUpperCase()}</b></span>
          </div>

          <div className="global-risk-actions">
            <button type="button" className="btn danger" onClick={()=>setPage('events')}>
              이벤트 모니터링에서 확인 · Event #{overviewRiskEvent.id||overviewRiskEvent.event_id}
            </button>
            <button type="button" className="btn ghost" onClick={()=>setOverviewAlertDismissedId(overviewRiskEventId)}>
              확인
            </button>
          </div>
        </div>
      )}
"""
    component = component[:pos] + alert + component[pos:]
    print('[PATCH] Overview alert UI inserted')

app = app[:start] + component + app[end:]

# 4) 검증
verify_scope = app[start:start+len(component)+200]
required = [
    "if(page==='overview')return null",
    'const overviewRiskEvent=',
    'overview-security-alert-v9',
    "setPage('events')",
]
missing = [x for x in required if x not in app]
if missing:
    raise RuntimeError('VERIFY FAILED: ' + ', '.join(missing))

APP.write_text(app, encoding='utf-8')
print('[VERIFY OK] overview alert + header removal applied')

# 5) CSS
css = CSS.read_text(encoding='utf-8')
marker = '/* ===== OVERVIEW SECURITY ALERT V9 ===== */'
if marker not in css:
    css += """

/* ===== OVERVIEW SECURITY ALERT V9 ===== */
.overview-security-alert-v9{
  position:fixed !important;
  top:18px !important;
  right:22px !important;
  z-index:2147483640 !important;
  width:min(470px,calc(100vw - 36px)) !important;
  display:block !important;
  visibility:visible !important;
  opacity:1 !important;
  pointer-events:auto !important;
}
.overview-security-alert-v9.critical{
  border-color:rgba(255,72,76,.88) !important;
  box-shadow:0 22px 70px rgba(0,0,0,.64),0 0 32px rgba(255,55,65,.18) !important;
}
"""
    CSS.write_text(css, encoding='utf-8')
    print('[WRITE] alert CSS')

print()
print('SENTINEL Overview Alert v9 COMPLETE')
print('- overview header removed')
print('- newest HIGH/CRITICAL always shows alert on overview')
print('- current alert dismisses with 확인')
print('- next risky event shows again')