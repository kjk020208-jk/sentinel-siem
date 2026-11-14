from pathlib import Path
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
CSS = ROOT / "sentinel-react-frontend" / "src" / "styles.css"

if not APP.exists() or not CSS.exists():
    print("ERROR: 이 파일은 siemueba 프로젝트 루트에서 실행해야 합니다.")
    print(r"예: C:\Users\김재경\PycharmProjects\siemueba")
    sys.exit(1)

app_text = APP.read_text(encoding="utf-8")
css_text = CSS.read_text(encoding="utf-8")

(APP.parent / "App.before_sidebar_polish.jsx").write_text(app_text, encoding="utf-8")
(CSS.parent / "styles.before_sidebar_polish.css").write_text(css_text, encoding="utf-8")

start = app_text.find("function Sidebar(")
end = app_text.find("function TopBar", start)

if start == -1 or end == -1:
    print("ERROR: Sidebar 함수 범위를 찾지 못했습니다.")
    sys.exit(1)

new_sidebar = r'''function Sidebar({page,setPage,autoRefresh,setAutoRefresh,refresh}){
  const [collapsed,setCollapsed]=useState(false)
  const [status,setStatus]=useState('')
  const [resetAllowed,setResetAllowed]=useState(false)

  const engines=[
    ['Rule Engine','정상'],
    ['Isolation Forest','정상'],
    ['User Baseline','정상'],
    ['Sequence Detection','정상'],
    ['Peer Group UEBA','정상'],
    ['Dynamic User Risk','정상'],
    ['Incident Correlation','정상'],
    ['PII Detection','정상'],
    ['LLM Analyst','준비']
  ]

  const iconMap={
    overview:'⌂',
    events:'◫',
    incidents:'◆',
    users:'◎',
    behavior:'✓',
    cert:'C'
  }

  const demo=async type=>{
    setStatus('실행 중...')
    try{
      const r=await(type==='normal'?api.demoNormal():api.demoAttack())
      setStatus(
        type==='normal'
          ? '정상 시나리오 완료'
          : `${r?.final_risk_level||'공격 시나리오 완료'} · Risk ${r?.final_risk_score??'-'}`
      )
      refresh()
    }catch(e){
      setStatus(`실패: ${e.message}`)
    }
  }

  const reset=async()=>{
    if(!resetAllowed)return
    setStatus('초기화 중...')
    try{
      await api.demoReset()
      setStatus('이벤트 데이터 초기화 완료')
      refresh()
    }catch(e){
      setStatus(`실패: ${e.message}`)
    }
  }

  return (
    <aside className={`sidebar ${collapsed?'collapsed':''}`}>
      <div className="sidebar-head">
        <div className="sidebar-brand">
          <div className="sidebar-brand-name">SENTINEL</div>
          {!collapsed&&(
            <div className="sidebar-brand-sub">
              SIEM / UEBA 보안 관제 플랫폼
            </div>
          )}
        </div>

        <button
          type="button"
          className="sidebar-toggle"
          onClick={()=>setCollapsed(v=>!v)}
          title={collapsed?'메뉴 펼치기':'메뉴 접기'}
        >
          {collapsed?'☰':'‹'}
        </button>
      </div>

      {!collapsed&&<div className="side-section">보안 관제</div>}

      {MENU.map(([id,label])=>(
        <button
          key={id}
          className={`nav-btn ${page===id?'active':''}`}
          onClick={()=>setPage(id)}
          title={label}
        >
          <span className="nav-mini">{iconMap[id]||'•'}</span>
          {!collapsed&&<span className="nav-label">{label}</span>}
        </button>
      ))}

      {!collapsed&&(
        <>
          <div className="side-section">탐지 엔진</div>

          {engines.map(([n,s])=>(
            <div className="engine-row" key={n}>
              <span>{n}</span>
              <span className={s==='정상'?'engine-online':'engine-ready'}>{s}</span>
            </div>
          ))}

          <div className="side-section">시연 제어</div>

          <button className="nav-btn" onClick={()=>demo('normal')}>
            <span className="nav-mini">▶</span>
            <span className="nav-label">정상 시나리오 실행</span>
          </button>

          <button className="nav-btn" onClick={()=>demo('attack')}>
            <span className="nav-mini">!</span>
            <span className="nav-label">공격 시나리오 실행</span>
          </button>

          <label className="sidebar-check">
            <input
              type="checkbox"
              checked={resetAllowed}
              onChange={e=>setResetAllowed(e.target.checked)}
            />
            전체 이벤트 삭제 허용
          </label>

          <button
            className="nav-btn"
            disabled={!resetAllowed}
            onClick={reset}
          >
            <span className="nav-mini">⌫</span>
            <span className="nav-label">이벤트 데이터 초기화</span>
          </button>

          {status&&<div className="sidebar-status">{status}</div>}

          <div className="side-section">시스템</div>

          <label className="refresh-row">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={e=>setAutoRefresh(e.target.checked)}
            />
            <span className={`switch ${autoRefresh?'on':''}`}/>
            <span>실시간 자동 갱신</span>
            <span className="info-dot">ⓘ</span>
          </label>

          <div className="side-note">
            {autoRefresh?'동기화 실시간 갱신 · 3초':'자동 갱신 중지'}
          </div>

          <button className="nav-btn refresh-btn" onClick={refresh}>
            <span className="nav-mini">↻</span>
            <span className="nav-label">이벤트 데이터 새로고침</span>
          </button>

          <div className="side-note">VM1 중앙 분석 서버</div>
          <div className="api-line">API · 127.0.0.1:8000</div>
        </>
      )}
    </aside>
  )
}

'''

app_text = app_text[:start] + new_sidebar + app_text[end:]

marker = "/* ===== SENTINEL SIDEBAR + TABLE POLISH FINAL ===== */"
if marker in css_text:
    css_text = css_text.split(marker)[0].rstrip() + "\n"

css_patch = r'''
/* ===== SENTINEL SIDEBAR + TABLE POLISH FINAL ===== */

.sidebar{
  width:240px !important;
  transition:width .24s ease,padding .24s ease !important;
  overflow-x:hidden !important;
}

.main{
  transition:margin-left .24s ease,width .24s ease !important;
}

.app-shell:has(.sidebar.collapsed) .main{
  margin-left:84px !important;
  width:calc(100% - 84px) !important;
}

.sidebar.collapsed{
  width:84px !important;
  padding-left:9px !important;
  padding-right:9px !important;
}

.sidebar-head{
  display:flex !important;
  align-items:flex-start !important;
  gap:8px !important;
  padding:13px 10px 17px !important;
  margin:0 0 12px !important;
  border-bottom:1px solid rgba(255,255,255,.055) !important;
}

.sidebar-brand{
  flex:1 !important;
  min-width:0 !important;
  margin:0 !important;
  padding:11px 7px !important;
  min-height:auto !important;
  background:transparent !important;
  border:0 !important;
  border-radius:0 !important;
  box-shadow:none !important;
  backdrop-filter:none !important;
  -webkit-backdrop-filter:none !important;
  overflow:visible !important;
}

.sidebar-brand::before,
.sidebar-brand::after{
  display:none !important;
  content:none !important;
}

.sidebar-brand,
.sidebar-brand *{
  background-color:transparent !important;
  background-image:none !important;
}

.sidebar-brand-name{
  margin:0 !important;
  padding:0 !important;
  color:#f5f7fa !important;
  font-size:17px !important;
  font-weight:760 !important;
  line-height:1.1 !important;
  letter-spacing:.17em !important;
  white-space:nowrap !important;
}

.sidebar-brand-sub{
  margin:9px 0 0 !important;
  padding:0 !important;
  color:#718093 !important;
  font-size:9px !important;
  line-height:1.45 !important;
  white-space:nowrap !important;
}

.sidebar-toggle{
  flex:0 0 34px !important;
  width:34px !important;
  height:34px !important;
  padding:0 !important;
  margin:4px 0 0 !important;
  display:grid !important;
  place-items:center !important;
  border:1px solid rgba(255,255,255,.09) !important;
  border-radius:11px !important;
  background:rgba(255,255,255,.045) !important;
  color:#b9c5d4 !important;
  box-shadow:inset 0 1px 0 rgba(255,255,255,.045) !important;
  cursor:pointer !important;
  font-size:17px !important;
}

.sidebar-toggle:hover{
  background:rgba(255,255,255,.08) !important;
  color:#fff !important;
}

.sidebar.collapsed .sidebar-head{
  justify-content:center !important;
  padding-left:0 !important;
  padding-right:0 !important;
}

.sidebar.collapsed .sidebar-brand{
  display:none !important;
}

.nav-btn{
  display:flex !important;
  align-items:center !important;
  gap:11px !important;
  width:100% !important;
  min-height:40px !important;
  margin:3px 0 !important;
  padding:0 12px !important;
  border-radius:11px !important;
}

.nav-mini{
  flex:0 0 22px !important;
  width:22px !important;
  display:inline-flex !important;
  align-items:center !important;
  justify-content:center !important;
  color:#7e9cc0 !important;
  font-size:12px !important;
  font-weight:700 !important;
}

.nav-label{
  min-width:0 !important;
  overflow:hidden !important;
  text-overflow:ellipsis !important;
  white-space:nowrap !important;
}

.sidebar.collapsed .nav-btn{
  justify-content:center !important;
  padding-left:0 !important;
  padding-right:0 !important;
}

.sidebar.collapsed .nav-label,
.sidebar.collapsed .side-section,
.sidebar.collapsed .engine-row,
.sidebar.collapsed .sidebar-check,
.sidebar.collapsed .sidebar-status,
.sidebar.collapsed .refresh-row,
.sidebar.collapsed .side-note,
.sidebar.collapsed .api-line{
  display:none !important;
}

.ov2-live-list{
  display:flex !important;
  flex-direction:column !important;
  gap:7px !important;
  padding:7px !important;
  background:rgba(19,24,31,.72) !important;
  border:1px solid rgba(255,255,255,.065) !important;
  border-radius:18px !important;
}

.ov2-live-row{
  display:grid !important;
  grid-template-columns:64px 88px 145px minmax(180px,1fr) 110px 70px !important;
  align-items:center !important;
  column-gap:14px !important;
  min-height:48px !important;
  padding:0 15px !important;
  margin:0 !important;
  border:1px solid transparent !important;
  border-radius:12px !important;
  background:transparent !important;
}

.ov2-live-row + .ov2-live-row{
  border-top:0 !important;
}

.ov2-live-row:hover{
  background:rgba(255,255,255,.035) !important;
  border-color:rgba(255,255,255,.045) !important;
}

.ov2-live-row > *{
  margin:0 !important;
  min-width:0 !important;
  line-height:1.2 !important;
}

.ov2-live-row span,
.ov2-live-row b,
.ov2-live-row strong,
.ov2-live-row em{
  overflow:hidden !important;
  text-overflow:ellipsis !important;
  white-space:nowrap !important;
}

.ov2-live-row em{
  text-align:right !important;
}

.table-wrap{
  width:100% !important;
  overflow:auto !important;
  border:1px solid rgba(255,255,255,.075) !important;
  border-radius:17px !important;
  background:#151b22 !important;
  box-shadow:none !important;
}

.table-wrap table{
  width:100% !important;
  border-collapse:separate !important;
  border-spacing:0 !important;
  table-layout:auto !important;
}

.table-wrap thead{
  background:#1b222b !important;
}

.table-wrap th{
  height:42px !important;
  padding:0 16px !important;
  color:#7f8b99 !important;
  font-size:10px !important;
  font-weight:600 !important;
  text-align:left !important;
  vertical-align:middle !important;
  white-space:nowrap !important;
  border:0 !important;
  border-bottom:1px solid rgba(255,255,255,.065) !important;
}

.table-wrap td{
  height:48px !important;
  padding:0 16px !important;
  color:#c9d0d8 !important;
  font-size:11px !important;
  text-align:left !important;
  vertical-align:middle !important;
  white-space:nowrap !important;
  border:0 !important;
  border-bottom:1px solid rgba(255,255,255,.038) !important;
}

.table-wrap tbody tr{
  background:transparent !important;
}

.table-wrap tbody tr:hover{
  background:#1c242d !important;
}

.table-wrap tbody tr:last-child td{
  border-bottom:0 !important;
}

.ov2-data-card{
  padding:0 !important;
  overflow:hidden !important;
  background:#151b22 !important;
}

.ov2-data-title{
  margin:0 !important;
  padding:17px 18px 13px !important;
  color:#e5e9ee !important;
  font-size:12px !important;
  font-weight:600 !important;
  border-bottom:1px solid rgba(255,255,255,.05) !important;
}

.ov2-data-card .table-wrap{
  border:0 !important;
  border-radius:0 !important;
}

.ov2-chart-card,
.ov2-risk-card{
  overflow:hidden !important;
}

.ov2-card-head{
  min-height:45px !important;
  padding-bottom:7px !important;
}

.ov2-card-head h4{
  line-height:1.3 !important;
}

.ov2-block{
  margin-top:48px !important;
}

.ov2-section-head{
  margin-bottom:14px !important;
}

@media (max-width:1250px){
  .ov2-live-row{
    grid-template-columns:58px 82px 125px minmax(130px,1fr) 95px 66px !important;
    column-gap:10px !important;
  }
}
'''

CSS.write_text(css_text.rstrip() + "\n\n" + css_patch, encoding="utf-8")
APP.write_text(app_text, encoding="utf-8")

print("")
print("==============================================")
print(" SENTINEL Sidebar/Table polish patch 완료")
print("==============================================")
print(" - SENTINEL 검은 블록 제거")
print(" - 사이드바 접기/펼치기 추가")
print(" - Live Activity 정렬 수정")
print(" - 표 헤더/행/패딩 정리")
print("")
print("백업도 자동 생성했습니다.")
