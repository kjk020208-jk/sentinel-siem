import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from './api.js'
import Plotly from 'plotly.js-dist-min'

const PAGE_META = {
  overview: ['내부자 위협 보안 관제 센터', '사용자 행동 분석 · 이상행동 탐지 · 보안 사고 대응'],
  events: ['보안 이벤트 모니터링', 'Windows 보안 이벤트 · 파일 접근 · USB · 프로세스 실행 모니터링'],
  incidents: ['보안 사고 분석', 'Incident Correlation · Attack Storyline · 연관 이벤트 · AI 보조 분석'],
  users: ['사용자 행동 분석', '사용자별 행동 패턴 · 위험도 · 활동 이력 분석'],
  behavior: ['행동 변화 승인 관리', 'Human-in-the-loop · 예외 승인 · 위험 유지 · 재관찰'],
  cert: ['CERT 100K 성능 검증', 'CERT Insider Threat Dataset r4.2 · 100,000건 기반 탐지 성능 평가'],
}

const MENU = [
  ['overview','보안 현황'], ['events','이벤트 모니터링'], ['incidents','보안 사고 분석'],
  ['users','사용자 행동 분석'], ['behavior','행동 승인 관리'], ['cert','CERT 100K 검증']
]

const koEvent=(v='-')=>({login_success:'로그인 성공',login_failure:'로그인 실패',login_failed:'로그인 실패',process_execution:'프로세스 실행',file_access:'파일 접근',usb_connected:'USB 연결',usb_connection:'USB 연결',document_analysis:'문서 분석'}[String(v).toLowerCase()]||v||'-')
const num=(v,d=0)=>Number.isFinite(Number(v))?Number(v):d
const arr=(v,keys=[])=>{if(Array.isArray(v))return v;for(const k of keys)if(Array.isArray(v?.[k]))return v[k];return []}
const fmt=v=>{if(!v)return'-';const d=new Date(v);if(Number.isNaN(d.getTime()))return String(v);const p=n=>String(n).padStart(2,'0');return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`}
const timeOnly=v=>{const s=fmt(v);return s.includes(' ')?s.split(' ')[1]:s}
const riskClass=(v='LOW')=>String(v).toLowerCase()
const objText=v=>typeof v==='object'&&v!==null?JSON.stringify(v):String(v??'-')

function usePolling(fn, interval=3000, refreshKey=0){
  const [data,setData]=useState(null),[error,setError]=useState(''),[latency,setLatency]=useState(null)
  useEffect(()=>{let active=true;const run=async()=>{const t=performance.now();try{const x=await fn();if(active){setData(x);setLatency(performance.now()-t);setError('')}}catch(e){if(active)setError(e.message)}};run();const id=setInterval(run,interval);return()=>{active=false;clearInterval(id)}},[interval,refreshKey])
  return [data,error,setData,latency]
}

export default function App(){
  const [page,setPage]=useState('overview'),[autoRefresh,setAutoRefresh]=useState(true),[refreshKey,setRefreshKey]=useState(0)
  const [eventsRaw,eventsErr,,eventsLatency]=usePolling(api.events,autoRefresh?3000:86400000,refreshKey)
  const [incRaw]=usePolling(api.incidents,autoRefresh?3000:86400000,refreshKey)
  const [usersRaw]=usePolling(api.users,autoRefresh?10000:86400000,refreshKey)
  const rawEvents=arr(eventsRaw,['events','items','value']).slice().sort((a,b)=>num(b.id)-num(a.id))
  const incidents=arr(incRaw,['incidents','items','value'])
  const users=arr(usersRaw,['users','items','value'])
  const activeUsers=useMemo(()=>new Set(users.filter(u=>u.monitoring_enabled===true||u.enabled===true||u.is_enabled===true).map(u=>String(u.username||u.user||'')).filter(Boolean)),[users])
  const events=useMemo(()=>activeUsers.size?rawEvents.filter(e=>activeUsers.has(String(e.user||''))):rawEvents,[rawEvents,activeUsers])
  const criticalOpen=incidents.filter(i=>String(i.severity||i.risk_level).toUpperCase()==='CRITICAL'&&String(i.status||'OPEN').toUpperCase()!=='CLOSED').sort((a,b)=>String(b.last_seen||'').localeCompare(String(a.last_seen||''))||num(b.id)-num(a.id))
  const latestIncident=criticalOpen[0]||incidents[0]
  const refresh=()=>setRefreshKey(x=>x+1)
  return <div className="app-shell"><Sidebar page={page} setPage={setPage} autoRefresh={autoRefresh} setAutoRefresh={setAutoRefresh} refresh={refresh}/><main className="main"><TopBar/><div className="content"><PageHeader page={page}/>
    {page==='overview'&&<Overview events={events} users={users} latestIncident={latestIncident} setPage={setPage} error={eventsErr} latency={eventsLatency}/>} 
    {page==='events'&&<EventsPage events={events}/>} 
    {page==='incidents'&&<IncidentsPage incidents={incidents} allEvents={events} initialId={latestIncident?.id}/>} 
    {page==='users'&&<UserAnalysisPage events={events} users={users} refresh={refresh}/>} 
    {page==='behavior'&&<BehaviorPage/>} 
    {page==='cert'&&<CertPage/>}<Footer/></div></main></div>
}

function Sidebar({page,setPage,autoRefresh,setAutoRefresh,refresh}){
  const [resetAllowed,setResetAllowed]=useState(false),[status,setStatus]=useState('')
  const engines=[['Rule Engine','정상'],['Isolation Forest','정상'],['User Baseline','정상'],['Sequence Detection','정상'],['Peer Group UEBA','정상'],['Dynamic User Risk','정상'],['Incident Correlation','정상'],['PII Detection','정상'],['LLM Analyst','준비']]
  const demo=async type=>{setStatus('실행 중...');try{const r=await(type==='normal'?api.demoNormal():api.demoAttack());setStatus(type==='normal'?'정상 시나리오 완료':`${r?.final_risk_level||'공격 시나리오 완료'} · Risk ${r?.final_risk_score??'-'}`);refresh()}catch(e){setStatus(`실패: ${e.message}`)}}
  const reset=async()=>{if(!resetAllowed)return;setStatus('초기화 중...');try{await api.demoReset();setStatus('이벤트 데이터 초기화 완료');refresh()}catch(e){setStatus(`실패: ${e.message}`)}}
  return <aside className="sidebar"><div className="sidebar-brand"><div className="sidebar-brand-name">SENTINEL</div><div className="sidebar-brand-sub">SIEM / UEBA 보안 관제 플랫폼</div></div><div className="side-section">보안 관제</div>
    {MENU.map(([id,label])=><button key={id} className={`nav-btn ${page===id?'active':''}`} onClick={()=>setPage(id)}>{label}</button>)}
    <div className="side-section">탐지 엔진</div>{engines.map(([n,s])=><div className="engine-row" key={n}><span>{n}</span><span className={s==='정상'?'engine-online':'engine-ready'}>{s}</span></div>)}
    <div className="side-section">시연 제어</div><button className="nav-btn" onClick={()=>demo('normal')}>정상 시나리오 실행</button><button className="nav-btn" onClick={()=>demo('attack')}>공격 시나리오 실행</button>
    <label className="sidebar-check"><input type="checkbox" checked={resetAllowed} onChange={e=>setResetAllowed(e.target.checked)}/> 전체 이벤트 삭제 허용</label><button className="nav-btn" disabled={!resetAllowed} onClick={reset}>이벤트 데이터 초기화</button>{status&&<div className="sidebar-status">{status}</div>}
    <div className="side-section">시스템</div><label className="refresh-row"><input type="checkbox" checked={autoRefresh} onChange={e=>setAutoRefresh(e.target.checked)}/><span className={`switch ${autoRefresh?'on':''}`}/><span>실시간 자동 갱신</span><span className="info-dot">ⓘ</span></label><div className="side-note">{autoRefresh?'동기화 실시간 갱신 · 3초':'자동 갱신 중지'}</div><button className="nav-btn refresh-btn" onClick={refresh}>이벤트 데이터 새로고침</button><div className="side-note">VM1 중앙 분석 서버</div><div className="api-line">API · 127.0.0.1:8000</div>
  </aside>
}
function TopBar(){return <header className="topbar"><div className="top-actions"><span className="deploy">Deploy</span><span className="system-online">● 시스템 정상</span></div></header>}
function PageHeader({page}){const[t,s]=PAGE_META[page];const[now,setNow]=useState(new Date());useEffect(()=>{const id=setInterval(()=>setNow(new Date()),1000);return()=>clearInterval(id)},[]);return <div className="soc-header"><div><div className="soc-title">{t}</div><div className="soc-subtitle">{s}</div></div><div className="header-right"><div className="header-time">{fmt(now)}</div></div></div>}
function SectionHeader({children}){return <div className="section-header"><div className="section-title">{children}</div><div className="section-line"/></div>}
function Notice({type='info',children}){return <div className={`notice ${type}`}>{children}</div>}
function Field({label,children}){return <label className="field"><span>{label}</span>{children}</label>}

function Overview({events,users,latestIncident,setPage,error,latency}){
  const levels=['LOW','MEDIUM','HIGH','CRITICAL'];const counts=levels.map(l=>[l,events.filter(e=>String(e.risk_level).toUpperCase()===l).length]);const anomaly=events.filter(e=>num(e.anomaly_score)>=50).length;const highCritical=events.filter(e=>['HIGH','CRITICAL'].includes(String(e.risk_level).toUpperCase())).length;const critical=counts[3][1];const enabledUsers=users.filter(u=>u.monitoring_enabled===true||u.enabled===true||u.is_enabled===true).length||new Set(events.map(e=>e.user).filter(Boolean)).size;const avg=events.length?events.reduce((s,e)=>s+num(e.risk_score),0)/events.length:0;const latest=events[0]
  const topEvents=events.slice().sort((a,b)=>num(b.risk_score)-num(a.risk_score)).slice(0,5),um={};events.forEach(e=>{const u=e.user||'-',x=um[u]||=( {user:u,count:0,sum:0,max:0} );x.count++;x.sum+=num(e.risk_score);x.max=Math.max(x.max,num(e.risk_score))});const topUsers=Object.values(um).map(x=>({...x,avg:x.sum/x.count})).sort((a,b)=>b.max-a.max||b.avg-a.avg).slice(0,5)
  const tm={};events.forEach(e=>{const k=koEvent(e.event_type);tm[k]=(tm[k]||0)+1});let types=Object.entries(tm).sort((a,b)=>b[1]-a[1]);if(types.length>6){const o=types.slice(6).reduce((s,x)=>s+x[1],0);types=types.slice(0,6);if(o)types.push(['기타',o])}
  const bc={OBSERVING:0,ACCEPTED:0,REJECTED:0},seen=new Set(),re=/행동 변화 검증:\s*([^/]+?)\s*\/\s*(OBSERVING|ACCEPTED|REJECTED)/g;events.forEach(e=>{let m;const t=String(e.reasons||'');while((m=re.exec(t))){const k=`${e.user}|${m[1].trim()}`;if(!seen.has(k)){seen.add(k);bc[m[2]]++}}re.lastIndex=0})
  const alerts=events.filter(e=>['HIGH','CRITICAL'].includes(String(e.risk_level).toUpperCase())).slice(0,20),recent60=events.filter(e=>{const t=new Date(e.timestamp||e.created_at).getTime();return Number.isFinite(t)&&Date.now()-t<=60000}).length
  return <>{latestIncident&&String(latestIncident.severity||latestIncident.risk_level).toUpperCase()==='CRITICAL'&&<CriticalAlert incident={latestIncident} onOpen={()=>setPage('incidents')}/>}<div className="live-strip"><b>LIVE EVENT</b><span>· 최신 ID {latest?.id??'-'}</span><span>· 최근 수집 {fmt(latest?.timestamp||latest?.created_at)}</span><span>· 현재 조회 구간 CRITICAL {critical}건</span></div><div className="feed-label">LIVE INGEST FEED</div><div className="live-feed">{events.slice(0,3).map(e=><div className="feed-row" key={e.id}><span>#{e.id}</span><span>{timeOnly(e.timestamp||e.created_at)}</span><b>{e.user||'-'}</b><b>{koEvent(e.event_type)}</b><span>Risk {num(e.risk_score).toFixed(2)}</span><em className={riskClass(e.risk_level)}>{String(e.risk_level||'LOW').toUpperCase()}</em></div>)}</div>{error&&<Notice type="error">API 연결 오류: {error}</Notice>}
    <SectionHeader>보안 현황</SectionHeader><div className="section-caption">최근 수집된 보안 이벤트를 기준으로 현재 위험 상태와 우선 확인이 필요한 항목을 요약합니다.</div><div className="kpis"><Kpi title="전체 이벤트" value={events.length} hint="수집된 전체 보안 이벤트"/><Kpi title="이상행동 탐지" value={anomaly} hint="Isolation Forest Score ≥ 50"/><Kpi title="고위험 이벤트" value={highCritical} hint="HIGH + CRITICAL" warning/><Kpi title="긴급 이벤트" value={critical} hint="즉시 확인이 필요한 이벤트" danger/><Kpi title="모니터링 사용자" value={enabledUsers} hint="관찰된 사용자 계정"/></div>
    <SectionHeader>한눈에 보는 보안 상태</SectionHeader><div className="visual-grid"><Panel title="위험 등급 분포"><RiskDonut counts={counts}/></Panel><Panel title="이벤트 유형 분포"><EventTypeDonut items={types}/></Panel><Panel title="최근 이벤트 평균 위험도" subtitle={`현재 상태: ${avg>=80?'심각':avg>=65?'높음':avg>=30?'주의':'낮음'}`}><Gauge value={avg}/></Panel></div><div className="chart-note">※ 현재 화면의 시각화는 최근 로딩된 이벤트를 기준으로 계산됩니다.</div>
    <SectionHeader>즉시 확인 필요</SectionHeader><div className="priority-grid"><div><div className="subheading">위험도 상위 이벤트 5건</div><TopEventTable events={topEvents}/></div><div><div className="subheading">현재 위험 사용자 TOP 5</div><TopUserTable users={topUsers}/></div></div>
    <SectionHeader>행동 변화 검증 현황</SectionHeader><div className="section-caption">새 IP·프로세스·장치가 현재 정상 기준선에 반영 가능한 상태인지 요약합니다.</div><div className="metric3"><MetricCard label="관찰 중" value={bc.OBSERVING}/><MetricCard label="정상 승인" value={bc.ACCEPTED}/><MetricCard label="학습 제외" value={bc.REJECTED}/></div>
    <SectionHeader>주요 보안 경보</SectionHeader><AlertTable events={alerts}/><SectionHeader>최근 보안 이벤트</SectionHeader><EventTable events={events.slice(0,50)} tall/>
    <SectionHeader>시스템 성능 / 운영 참고</SectionHeader><div className="section-caption">사고 판단과 직접 관련된 지표가 아니라 현재 수집·API 상태를 확인하기 위한 운영 참고 정보입니다.</div><div className="metric4"><MetricCard label="최근 60초 이벤트" value={recent60}/><MetricCard label="관측 EPS" value={(recent60/60).toFixed(2)}/><MetricCard label="/events 응답 지연" value={latency==null?'-':`${latency.toFixed(1)} ms`}/><MetricCard label="현재 조회 이벤트" value={events.length}/></div></>
}
function CriticalAlert({incident,onOpen}){
  const signature=[incident?.id??incident?.incident_id??'',incident?.last_seen??incident?.updated_at??incident?.created_at??'',incident?.correlation_score??''].join('|')
  const storageKey='sentinel_acknowledged_critical_alerts'
  const readAcked=()=>{try{return new Set(JSON.parse(localStorage.getItem(storageKey)||'[]'))}catch{return new Set()}}
  const[hidden,setHidden]=useState(()=>readAcked().has(signature))
  useEffect(()=>{setHidden(readAcked().has(signature))},[signature])
  const acknowledge=()=>{
    const acked=readAcked();acked.add(signature)
    try{localStorage.setItem(storageKey,JSON.stringify([...acked].slice(-100)))}catch{}
    setHidden(true)
  }
  if(hidden)return null
  return <div className="critical-alert"><div className="live-alert-top"><div className="live-alert-title">● LIVE CRITICAL INCIDENT</div><div className="live-alert-time">{fmt(incident.last_seen||incident.updated_at||incident.created_at)}</div></div><div className="live-alert-main">{incident.title||incident.incident_type||'보안 사고 감지'}</div><div className="live-alert-meta">확인되지 않은 OPEN CRITICAL Incident가 있습니다.<br/>Incident #{incident.id||incident.incident_id} · 사용자 {incident.user||incident.username||'-'} · Correlation {num(incident.correlation_score).toFixed(1)} · OPEN CRITICAL 1건</div><div className="alert-actions"><button className="btn danger" onClick={onOpen}>사고 상세 보기 · Incident #{incident.id||incident.incident_id}</button><button className="btn ghost" onClick={acknowledge}>확인</button></div></div>
}
function Kpi({title,value,hint,warning,danger}){return <div className="kpi-card"><div className="kpi-label">{title}</div><div className={`kpi-value ${warning?'kpi-warning':''} ${danger?'kpi-danger':''}`}>{typeof value==='number'?value.toLocaleString():value}</div><div className="kpi-foot">{hint}</div></div>}
function MetricCard({label,value,foot}){return <div className="metric-card"><span>{label}</span><strong>{value}</strong>{foot&&<small>{foot}</small>}</div>}
function StMetric({label,value,help}){return <div className="st-metric"><div className="st-metric-label">{label}</div><div className="st-metric-value">{typeof value==='number'?value.toLocaleString():value}</div>{help&&<div className="st-metric-help">{help}</div>}</div>}
function IncidentKpi({label,value,foot}){return <div className="incident-kpi"><div className="incident-kpi-label">{label}</div><div className="incident-kpi-value">{value}</div><div className="incident-kpi-foot">{foot}</div></div>}
function Panel({title,subtitle,children}){return <section className="panel"><div className="panel-title">{title}</div>{subtitle&&<div className="panel-subtitle">{subtitle}</div>}{children}</section>}

function PlotlyChart({data,layout={},config={},className=''}){
  const ref=useRef(null)
  useEffect(()=>{
    if(!ref.current)return
    const baseLayout={paper_bgcolor:'rgba(0,0,0,0)',plot_bgcolor:'rgba(0,0,0,0)',font:{family:'Pretendard, Noto Sans KR, Segoe UI, sans-serif',color:'#cbd5e1',size:11},margin:{l:45,r:20,t:25,b:45},...layout}
    const baseConfig={responsive:true,displaylogo:false,scrollZoom:true,modeBarButtonsToRemove:['lasso2d','select2d'],...config}
    Plotly.react(ref.current,data,baseLayout,baseConfig)
    return ()=>{try{Plotly.purge(ref.current)}catch{}}
  },[JSON.stringify(data),JSON.stringify(layout),JSON.stringify(config)])
  return <div ref={ref} className={`plotly-host ${className}`}/>
}
function InteractiveDonut({items,centerTop,centerBottom}){
  const labels=items.map(x=>x[0]),values=items.map(x=>num(x[1])),total=values.reduce((a,b)=>a+b,0)||1
  return <div className="donut-area plotly-donut-area"><PlotlyChart className="plotly-donut" data={[{type:'pie',hole:.58,labels,values,textinfo:'percent',textposition:'auto',insidetextorientation:'horizontal',hovertemplate:'<b>%{label}</b><br>%{value}건<br>%{percent}<extra></extra>',sort:false,marker:{line:{color:'#080c14',width:1}}}]} layout={{height:280,showlegend:true,legend:{orientation:'h',x:.5,xanchor:'center',y:-.06,font:{size:10}},margin:{l:8,r:8,t:8,b:52},annotations:[{text:`<b>${centerTop}</b><br><span style="font-size:10px;color:#94a3b8">${centerBottom}</span>`,x:.5,y:.5,showarrow:false,font:{size:18,color:'#f1f5f9'}}]}} config={{displayModeBar:false,scrollZoom:false}}/></div>
}
function RiskDonut({counts}){const labels={LOW:'낮음',MEDIUM:'주의',HIGH:'높음',CRITICAL:'심각'};const items=counts.map(x=>[labels[x[0]]||x[0],x[1]]);return <InteractiveDonut items={items} centerTop={counts.reduce((s,x)=>s+x[1],0)} centerBottom="전체 이벤트"/>}
function EventTypeDonut({items}){return <InteractiveDonut items={items} centerTop={items[0]?.[0]||'-'} centerBottom="최다유형"/>}
function Gauge({value}){const v=Math.max(0,Math.min(100,num(value)));const a=Math.PI*(1-v/100);const x=100+78*Math.cos(a),y=100-78*Math.sin(a);const large=v>50?1:0;return <div className="gauge-shell svg-gauge"><svg viewBox="0 0 200 125"><path d="M22 100 A78 78 0 0 1 178 100" fill="none" stroke="#182230" strokeWidth="18"/><path d="M22 100 A78 78 0 0 1 63 31" fill="none" stroke="#1f6b3b" strokeWidth="18"/><path d="M63 31 A78 78 0 0 1 118 24" fill="none" stroke="#6b5d15" strokeWidth="18"/><path d="M118 24 A78 78 0 0 1 156 51" fill="none" stroke="#6b3f15" strokeWidth="18"/><path d="M156 51 A78 78 0 0 1 178 100" fill="none" stroke="#5a1d26" strokeWidth="18"/><path d={`M22 100 A78 78 0 ${large} 1 ${x.toFixed(2)} ${y.toFixed(2)}`} fill="none" stroke="#3187e8" strokeWidth="8" strokeLinecap="round"><title>현재 평균 Risk ${v.toFixed(1)}점</title></path><text x="100" y="94" textAnchor="middle" className="gauge-value">{v.toFixed(1)}점</text><text x="18" y="116" className="gauge-tick">0</text><text x="52" y="48" className="gauge-tick">20</text><text x="82" y="24" className="gauge-tick">40</text><text x="112" y="24" className="gauge-tick">60</text><text x="145" y="48" className="gauge-tick">80</text><text x="174" y="116" className="gauge-tick">100</text></svg></div>}
function TopEventTable({events}){return <SimpleTable headers={['발생 시간','사용자','이벤트','위험도','등급']} rows={events.map(e=>[fmt(e.timestamp||e.created_at),e.user||'-',koEvent(e.event_type),num(e.risk_score).toFixed(2),String(e.risk_level||'LOW').toUpperCase()])} short/>}
function TopUserTable({users}){return <SimpleTable headers={['사용자','최고위험도','평균위험도','이벤트수']} rows={users.map(u=>[u.user,u.max.toFixed(2),u.avg.toFixed(2),u.count])} short/>}
function AlertTable({events}){return <SimpleTable headers={['탐지 시간','위험 등급','Risk Score','사용자','이벤트 유형','Source IP','파일','프로세스']} rows={events.map(e=>[fmt(e.timestamp||e.created_at),e.risk_level||'-',num(e.risk_score).toFixed(2),e.user||'-',koEvent(e.event_type),e.source_ip||'-',e.file_name||e.file_path||'-',e.process_name||'-'])}/>} 
function EventTable({events,tall=false}){return <SimpleTable tall={tall} headers={['이벤트 ID','발생 시간','사용자','이벤트 유형','Source IP','로그인 실패','파일','파일 등급','파일 접근','USB','프로세스','Anomaly Score','Risk Score','위험 등급']} rows={events.map(e=>[e.id,fmt(e.timestamp||e.created_at),e.user||'-',koEvent(e.event_type),e.source_ip||'-',e.login_fail_count??'-',e.file_name||e.file_path||'-',e.file_grade||'-',e.file_access_count??'-',e.usb_connected??'-',e.process_name||'-',num(e.anomaly_score).toFixed(2),num(e.risk_score).toFixed(2),e.risk_level||'-'])}/>} 
function SimpleTable({headers,rows,short=false,tall=false}){return <div className={`table-wrap ${short?'short':''} ${tall?'tall':''}`}><table><thead><tr>{headers.map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{rows.length?rows.map((r,i)=><tr key={i}>{r.map((c,j)=><td key={j}>{c}</td>)}</tr>):<tr><td colSpan={headers.length} className="empty-cell">표시할 데이터가 없습니다.</td></tr>}</tbody></table></div>}

function EventsPage({events}){
  const[level,setLevel]=useState('전체'),[user,setUser]=useState('전체'),[type,setType]=useState('전체'),[search,setSearch]=useState(''),[selectedBehavior,setSelectedBehavior]=useState(''),[selectedExplain,setSelectedExplain]=useState(''),[explanation,setExplanation]=useState(null),[exErr,setExErr]=useState(''),[eventAI,setEventAI]=useState(null),[eventAiError,setEventAiError]=useState(''),[aiBusy,setAiBusy]=useState(false)
  const levels=['전체',...new Set(events.map(e=>e.risk_level).filter(Boolean))],users=['전체',...new Set(events.map(e=>e.user).filter(Boolean))],types=['전체',...new Set(events.map(e=>koEvent(e.event_type)).filter(Boolean))]
  const filtered=events.filter(e=>(level==='전체'||e.risk_level===level)&&(user==='전체'||String(e.user)===user)&&(type==='전체'||koEvent(e.event_type)===type)&&(!search.trim()||[e.user,e.source_ip,e.file_name,e.file_path,e.process_name].some(v=>String(v||'').toLowerCase().includes(search.trim().toLowerCase()))))
  const behaviorEvents=filtered.filter(e=>String(e.reasons||'').includes('행동 변화 검증:')),explainables=filtered.filter(e=>e.id!=null)
  useEffect(()=>{if(!selectedBehavior&&behaviorEvents[0])setSelectedBehavior(String(behaviorEvents[0].id));if(!selectedExplain&&explainables[0])setSelectedExplain(String(explainables[0].id))},[filtered.length])
  const bEvent=behaviorEvents.find(e=>String(e.id)===String(selectedBehavior));const behaviorItems=[];String(bEvent?.reasons||'').split(',').forEach(reason=>{reason=reason.trim();if(!reason.startsWith('행동 변화 검증:'))return;const p=reason.replace('행동 변화 검증:','').trim().split(' / ');behaviorItems.push({target:p[0],status:String(p[1]||'OBSERVING').toUpperCase(),reason:p.slice(2).join(' / ')||'-'})})
  const loadExplain=async()=>{setExErr('');setExplanation(null);try{setExplanation(await api.riskExplanation(selectedExplain))}catch(e){setExErr(e.message)}}
  const runAI=async()=>{
    setAiBusy(true)
    setEventAiError('')
    setEventAI(null)
    try{
      const r=await api.eventAI(selectedExplain)
      setEventAI(r)
    }catch(e){
      setEventAiError(e?.message||'AI 보안 분석 요청에 실패했습니다.')
    }finally{
      setAiBusy(false)
    }
  }
  return <><SectionHeader>이벤트 필터</SectionHeader><div className="filter-grid"><Field label="위험 등급"><select value={level} onChange={e=>setLevel(e.target.value)}>{levels.map(x=><option key={x}>{x}</option>)}</select></Field><Field label="사용자"><select value={user} onChange={e=>setUser(e.target.value)}>{users.map(x=><option key={x}>{x}</option>)}</select></Field><Field label="이벤트 유형"><select value={type} onChange={e=>setType(e.target.value)}>{types.map(x=><option key={x}>{x}</option>)}</select></Field></div><Field label="검색"><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="사용자, IP, 파일명, 프로세스명 검색"/></Field>
    <SectionHeader>모니터링 현황</SectionHeader><div className="kpis compact"><Kpi title="조회 이벤트" value={filtered.length} hint="현재 필터 조건"/><Kpi title="CRITICAL" value={filtered.filter(e=>e.risk_level==='CRITICAL').length} hint="긴급 위험 이벤트" danger/><Kpi title="HIGH" value={filtered.filter(e=>e.risk_level==='HIGH').length} hint="고위험 이벤트" warning/><Kpi title="사용자" value={new Set(filtered.map(e=>e.user).filter(Boolean)).size} hint="조회된 사용자"/></div>
    <SectionHeader>보안 이벤트 로그</SectionHeader><EventTable events={filtered} tall/>
    <SectionHeader>행동 변화 검증</SectionHeader><div className="section-caption">새로운 IP·프로세스·장치를 즉시 정상으로 학습하지 않고 관찰 후 ACCEPTED 또는 REJECTED 상태로 판정합니다.</div>{behaviorEvents.length?<><Field label="행동 변화 검증 이벤트"><select value={selectedBehavior} onChange={e=>setSelectedBehavior(e.target.value)}>{behaviorEvents.map(e=><option value={e.id} key={e.id}>#{e.id} · {e.user} · {koEvent(e.event_type)} · {e.risk_level}</option>)}</select></Field><div className="st-metric-grid cols3"><StMetric label="관찰 중" value={behaviorItems.filter(x=>x.status==='OBSERVING').length}/><StMetric label="정상 승인" value={behaviorItems.filter(x=>x.status==='ACCEPTED').length}/><StMetric label="학습 제외" value={behaviorItems.filter(x=>x.status==='REJECTED').length}/></div><div className="behavior-cards">{behaviorItems.map((x,i)=><Notice key={i} type={x.status==='REJECTED'?'error':x.status==='ACCEPTED'?'success':'warning'}><b>{x.status} · {x.target}</b><br/>{x.reason}</Notice>)}</div></>:<Notice>현재 표시 중인 이벤트에는 행동 변화 검증 결과가 없습니다.</Notice>}
    <SectionHeader>Explainable Risk Score</SectionHeader><div className="section-caption">선택한 이벤트의 Rule / Baseline / ML / Sequence / Peer / Adaptive 점수와 위험도 보정 근거를 확인합니다.</div><div className="action-row"><select className="select grow" value={selectedExplain} onChange={e=>{setSelectedExplain(e.target.value);setExplanation(null);setEventAI(null)}}>{explainables.map(e=><option value={e.id} key={e.id}>#{e.id} · {e.user} · {koEvent(e.event_type)} · Risk {num(e.risk_score).toFixed(2)}</option>)}</select><button className="btn primary" onClick={loadExplain}>위험도 근거 조회</button><button type="button" className="btn primary" disabled={aiBusy} onClick={runAI}>{aiBusy?'AI 분석 중...':'개별 이벤트 AI 분석'}</button></div>{exErr&&<Notice type="error">{exErr}</Notice>}{explanation&&<RiskExplanation data={explanation}/>} {eventAiError&&<Notice type="error">AI 보안 분석 실패 · {eventAiError}</Notice>}{eventAI&&<EventAIReport response={eventAI}/>}
  </>
}
function RiskExplanation({data}){
  if(!data)return null
  const historical=Boolean(data.historical_fallback)
  const components=Array.isArray(data.components)?data.components:[]
  const receipt=Array.isArray(data.score_receipt)?data.score_receipt:[]
  const reasons=Array.isArray(data.reasons)?data.reasons:[]
  const thresholdGuide=data.threshold_guide&&typeof data.threshold_guide==='object'?Object.values(data.threshold_guide):[]
  const finalScore=num(data.final_score??data.risk_score)
  const level=data.risk_level||'-'
  const before=data.score_before_floor
  const summary=data.plain_summary
  const decision=data.decision_text

  if(historical){
    return <div className="risk-explain-streamlit">
      {summary&&<Notice>{summary}</Notice>}
      <div className="section-caption">{data.note||'과거 이벤트의 상세 구성 점수는 저장되어 있지 않습니다.'}</div>
      <div className="st-metric-grid cols2">
        <StMetric label="최종 Event Risk" value={finalScore.toFixed(2)}/>
        <StMetric label="위험 등급" value={level}/>
      </div>
      {reasons.length>0&&<><div className="streamlit-bold">탐지 근거</div><div className="evidence-list">{reasons.map((r,i)=><div className="evidence-item" key={i}><div className="evidence-number">{String(i+1).padStart(2,'0')}</div><div>{r}</div></div>)}</div></>}
      {decision&&<><div className="streamlit-bold">관리자 판단</div><div className="plain-text-block">{decision}</div></>}
    </div>
  }

  return <div className="risk-explain-streamlit">
    {summary&&<Notice>{summary}</Notice>}
    <div className="section-caption">최종 점수가 어떤 탐지 계층의 기여로 만들어졌는지 이벤트 발생 당시 계산값을 일반인도 이해할 수 있도록 풀어 표시합니다.</div>

    {components.length>0&&<div className={`component-metric-grid cols${Math.min(6,components.length)}`}>
      {components.map((c,i)=>{
        const contribution=num(c.contribution)
        const sign=contribution>0?'+':''
        return <div className="component-metric" key={c.key||i} title={c.plain_explanation||c.description||''}>
          <div className="component-metric-label">{c.label||c.key||`탐지 계층 ${i+1}`}</div>
          <div className={`component-metric-value ${contribution<0?'negative':''}`}>{sign}{contribution.toFixed(2)}</div>
          <div className="component-metric-help">{c.plain_explanation||c.description||''}</div>
        </div>
      })}
    </div>}

    <div className="streamlit-bold">점수 영수증</div>
    {receipt.length?<ul className="score-receipt">{receipt.map((line,i)=><li key={i}>{line}</li>)}</ul>:<div className="section-caption">저장된 점수 영수증 정보가 없습니다.</div>}

    <div className="streamlit-bold">왜 이 점수가 나왔는가</div>
    {components.length?<div className="component-explanations">{components.map((c,i)=><div key={c.key||i}>- <b>{c.label||c.key||'탐지 계층'}</b> · {c.plain_explanation||c.description||'설명 없음'}</div>)}</div>:<div className="section-caption">구성 점수 정보가 없습니다.</div>}

    <div className="st-metric-grid cols3 risk-final-metrics">
      <StMetric label="안전장치 적용 전" value={before==null?'-':num(before).toFixed(2)}/>
      <StMetric label="최종 Event Risk" value={finalScore.toFixed(2)}/>
      <StMetric label="최종 위험 등급" value={level}/>
    </div>

    {data.floor_applied?<Notice type="warning">위험도 최소 보장 안전장치 적용 · {data.floor_reason||'고위험 탐지 신호에 따른 최소 위험도 적용'}</Notice>:<div className="section-caption">Sequence/Baseline 최소 위험도 안전장치의 추가 상향은 없었습니다.</div>}
    {decision&&<><div className="streamlit-bold">관리자 판단</div><div className="plain-text-block">{decision}</div></>}
    {thresholdGuide.length>0&&<div className="section-caption">위험 등급 기준 · {thresholdGuide.join(' / ')}</div>}
    {data.calculation_explanation&&<details className="streamlit-expander"><summary>위험점수가 필요한 이유</summary><div>{data.calculation_explanation}</div></details>}
    <div className="section-caption">{data.note||'Dynamic User Risk와 Incident Score는 Event Risk와 별도입니다.'}</div>
  </div>
}

function IncidentSelector({incidents,selectedId,setSelectedId}){return <select className="select" value={selectedId||''} onChange={e=>setSelectedId(e.target.value)}>{incidents.map(i=>{const iid=i.id||i.incident_id;const sev=String(i.severity||i.risk_level||'-').toUpperCase();const stat=String(i.status||'OPEN').toUpperCase();const user=i.user||i.username||'-';const corr=num(i.correlation_score).toFixed(1);const title=i.title||i.incident_type||'보안 사고';return <option key={iid} value={iid}>{`${iid}  |  ${sev}  |  ${stat}  |  ${user}  |  Correlation ${corr}  |  ${title}`}</option>})}</select>}
function IncidentsPage({incidents,allEvents=[],initialId}){
  const[level,setLevel]=useState('전체'),[status,setStatus]=useState('전체'),[id,setId]=useState(initialId||incidents[0]?.id||''),[detail,setDetail]=useState(null),[err,setErr]=useState(''),[ai,setAi]=useState(null),[incidentAiError,setIncidentAiError]=useState(''),[aiBusy,setAiBusy]=useState(false),[playbook,setPlaybook]=useState(null),[selectedEvent,setSelectedEvent]=useState(''),[eventExplain,setEventExplain]=useState(null),[eventAI,setEventAI]=useState(null),[eventAiError,setEventAiError]=useState(''),[eventAiBusy,setEventAiBusy]=useState(false)
  const filtered=incidents.filter(i=>(level==='전체'||String(i.severity||i.risk_level).toUpperCase()===level)&&(status==='전체'||String(i.status||'OPEN').toUpperCase()===status))
  useEffect(()=>{if(!filtered.some(i=>String(i.id||i.incident_id)===String(id))&&filtered[0])setId(String(filtered[0].id||filtered[0].incident_id))},[level,status,incidents.length])
  useEffect(()=>{
    if(!id)return
    setErr('')
    setAi(null)
    setIncidentAiError('')
    setEventAI(null)
    setEventAiError('')
    setEventExplain(null)
    api.incident(id).then(d=>{
      setDetail(d)
      const ev=incidentEvents(d,allEvents)
      if(ev[0])setSelectedEvent(String(ev[0].id||ev[0].event_id))
    }).catch(e=>setErr(e.message))
    api.playbook(id).then(setPlaybook).catch(()=>setPlaybook(null))
  },[id])
  const inc=detail||filtered.find(i=>String(i.id||i.incident_id)===String(id))||null
  const evs=incidentEvents(inc,allEvents)
  const storyRaw=arr(inc?.storyline,['attack_storyline','timeline','events'])
  const story=storyRaw.length?storyRaw:evs
  const eventLookup=Object.fromEntries(evs.map(e=>[String(e.id||e.event_id),e]))
  const runIncidentAI=async()=>{
    setAiBusy(true)
    setIncidentAiError('')
    setAi(null)
    try{
      const r=await api.incidentAI(id)
      setAi(r)
    }catch(e){
      setIncidentAiError(e?.message||'Incident AI SOC 분석 요청에 실패했습니다.')
    }finally{
      setAiBusy(false)
    }
  }
  const updateStep=async(step,action)=>{try{await api.playbookStep(id,step.id||step.step_id,action);setPlaybook(await api.playbook(id))}catch(e){setErr(e.message)}}
  const explainEvent=async()=>{try{setEventExplain(await api.riskExplanation(selectedEvent))}catch(e){setErr(e.message)}}
  const aiEvent=async()=>{
    setEventAiBusy(true)
    setEventAiError('')
    setEventAI(null)
    try{
      const r=await api.eventAI(selectedEvent)
      setEventAI(r)
    }catch(e){
      setEventAiError(e?.message||'선택 이벤트 AI 분석 요청에 실패했습니다.')
    }finally{
      setEventAiBusy(false)
    }
  }
  if(!incidents.length)return <Notice type="warning">Incident Correlation 결과가 없습니다. 공격 시나리오를 실행한 뒤 새로고침하십시오.</Notice>
  return <><SectionHeader>Incident Correlation</SectionHeader><div className="incident-filter-grid"><Field label="사고 심각도"><select value={level} onChange={e=>setLevel(e.target.value)}><option>전체</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></Field><Field label="상태"><select value={status} onChange={e=>setStatus(e.target.value)}><option>전체</option><option>OPEN</option><option>CLOSED</option></select></Field><div className="incident-filter-caption">여러 보안 이벤트를 사용자 · 시간 · 공격 단계 기준으로 상관분석하여 하나의 조사 가능한 사고로 재구성합니다.</div></div><Field label="분석할 보안 사고를 선택하세요."><IncidentSelector incidents={filtered} selectedId={id} setSelectedId={setId}/></Field>{err&&<Notice type="error">{err}</Notice>}{inc&&<><div className="incident-correlation-shell"><div className="incident-correlation-top"><div><div className="incident-correlation-id">INCIDENT #{id}</div><div className="incident-correlation-title">{inc.title||inc.incident_type||'보안 사고'}</div><div className="incident-correlation-meta">사용자 {inc.user||inc.username||'-'} · Correlation {num(inc.correlation_score).toFixed(1)} · 관련 이벤트 {evs.length}건 · 최근 {fmt(inc.last_seen||inc.updated_at)}</div></div><span className="incident-status-badge">{String(inc.severity||inc.risk_level||'CRITICAL').toUpperCase()} · {inc.status||'OPEN'}</span></div></div>
    <div className="incident-kpi-grid"><IncidentKpi label="Correlation Score" value={num(inc.correlation_score).toFixed(0)} foot="다중 이벤트 상관분석"/><IncidentKpi label="공격 단계" value={story.length} foot="Storyline 단계 수"/><IncidentKpi label="연관 이벤트" value={evs.length} foot="사고에 연결된 이벤트"/><IncidentKpi label="최대 Event Risk" value={Math.max(0,...evs.map(e=>num(e.risk_score))).toFixed(2)} foot={String(evs.slice().sort((a,b)=>num(b.risk_score)-num(a.risk_score))[0]?.risk_level||'-')}/></div>
    <SectionHeader>Attack Storyline</SectionHeader><div className="section-caption">Sequence Detection이 실시간 공격 순서를 점수화한다면, Incident Correlation은 저장된 여러 이벤트를 조사 가능한 공격 스토리로 재구성합니다.</div><Storyline events={story} eventLookup={eventLookup}/>
    <SectionHeader>AI SOC Analyst</SectionHeader><div className="section-caption">OpenAI API가 선택한 Incident의 Storyline, Event Risk, MITRE ATT&CK, Dynamic User Risk를 함께 해석합니다. AI는 탐지 점수를 결정하지 않고 조사 의사결정을 보조합니다.</div><button type="button" className="btn primary incident-ai-button" disabled={aiBusy} onClick={runIncidentAI}>{aiBusy?'OpenAI API가 Incident 전체 증거를 분석하고 있습니다...':'Incident 전체 AI 분석 실행'}</button>{incidentAiError&&<Notice type="error">AI SOC 분석 실패 · {incidentAiError}</Notice>}{ai&&<IncidentAIReport response={ai}/>}
    <SectionHeader>Response Playbook · SOAR-lite</SectionHeader><div className="section-caption">Incident 유형과 증거에 따라 사전 정의된 대응 절차를 추천합니다. 현재 MVP는 실제 계정 잠금·네트워크 차단을 자동 실행하지 않으며, 관리자 승인과 처리 상태를 기록합니다.</div><PlaybookView data={playbook} incidentId={id} onAction={updateStep}/>
    <SectionHeader>연관 이벤트</SectionHeader><EventTable events={evs} tall/>
    <SectionHeader>연관 이벤트 상세 분석</SectionHeader>{evs.length>0&&<RelatedEventDetail events={evs} selectedEvent={selectedEvent} setSelectedEvent={v=>{setSelectedEvent(v);setEventExplain(null);setEventAI(null);setEventAiError('')}} onExplain={explainEvent} onAI={aiEvent} explanation={eventExplain} ai={eventAI} aiError={eventAiError} aiBusy={eventAiBusy}/>}

  </>}</>
}
function RelatedEventDetail({events,selectedEvent,setSelectedEvent,onExplain,onAI,explanation,ai,aiError,aiBusy}){
  const e=events.find(x=>String(x.id||x.event_id)===String(selectedEvent))||events[0]
  if(!e)return null
  const reasons=String(e.reasons||'').split(',').map(x=>x.trim()).filter(Boolean)
  const level=String(e.risk_level||'-').toUpperCase()
  const risk=num(e.risk_score).toFixed(2)
  return <>
    <Field label="상세 분석할 연관 이벤트를 선택하세요.">
      <select value={selectedEvent} onChange={x=>setSelectedEvent(x.target.value)}>
        {events.map(x=><option key={x.id||x.event_id} value={x.id||x.event_id}>#{x.id||x.event_id} | {String(x.risk_level||'-').toUpperCase()} | {koEvent(x.event_type)} | Risk {num(x.risk_score).toFixed(2)}</option>)}
      </select>
    </Field>
    <div className="detail-grid related-detail-grid">
      <Detail label="사용자" value={e.user||'-'}/>
      <Detail label="Source IP" value={e.source_ip||'-'}/>
      <Detail label="접근 파일" value={e.file_name||e.file_path||'-'}/>
      <Detail label="로그인 실패 횟수" value={e.login_fail_count??0}/>
      <Detail label="이벤트 유형" value={koEvent(e.event_type)}/>
      <Detail label="실행 프로세스" value={e.process_name||'-'}/>
      <Detail label="파일 등급" value={e.file_grade||'-'}/>
      <Detail label="파일 접근 횟수" value={e.file_access_count??0}/>
    </div>
    <SectionHeader>탐지 근거</SectionHeader>
    {reasons.length
      ? <div className="evidence-list">{reasons.map((r,i)=><div className="evidence-item" key={i}><div className="evidence-number">{String(i+1).padStart(2,'0')}</div><div>{r}</div></div>)}</div>
      : <Notice>현재 이벤트에 기록된 탐지 근거가 없습니다.</Notice>}
    <SectionHeader>Explainable Risk Score · 점수 영수증</SectionHeader>
    <div className="action-row related-actions">
      <button type="button" className="btn primary" onClick={onExplain}>위험도 근거 조회</button>
    </div>
    {explanation&&<RiskExplanation data={explanation}/>}
    <SectionHeader>규칙 기반 대응 권고</SectionHeader>
    {level==='CRITICAL'
      ? <Notice type="error">상관분석 결과 다단계 고위험 사고로 판단되었습니다. 사용자 세션·인증 기록·민감정보 접근·USB 및 외부 전송 가능 프로세스를 우선 조사하십시오.</Notice>
      : level==='HIGH'
        ? <Notice type="warning">복수의 위험 행동이 하나의 사고로 연결되었습니다. 연관 이벤트의 시간 순서와 사용자 행위를 우선 확인하십시오.</Notice>
        : <Notice>연관 이벤트의 추가 발생 여부와 사용자 행동 변화를 지속적으로 확인하십시오.</Notice>}
    <SectionHeader>AI 보안 사고 분석</SectionHeader>
    <div className="section-caption">LLM은 선택한 연관 이벤트의 기존 탐지 결과를 해석하는 보조 분석 계층이며 Risk Score나 Incident Correlation 결과를 변경하지 않습니다.</div>
    <div className="event-ai-row">
      <button type="button" className="btn primary" disabled={aiBusy} onClick={onAI}>{aiBusy?'AI 분석 중...':'선택 이벤트 AI 분석'}</button>
      <div className="section-caption">Event #{e.id||e.event_id} · {level} · Risk {risk}</div>
    </div>
    {aiError&&<Notice type="error">AI 보안 분석 요청에 실패했습니다. · {aiError}</Notice>}
    {ai&&<EventAIReport response={ai}/>}
  </>
}

function incidentEvents(inc,allEvents=[]){
  if(!inc)return[]
  const fullById=Object.fromEntries((allEvents||[]).map(e=>[String(e.id||e.event_id),e]))
  let base=[]
  for(const k of ['related_events','events','event_list']){if(Array.isArray(inc[k])&&inc[k].length){base=inc[k];break}}
  const ids=arr(inc.event_ids||inc.related_event_ids)
  if(!base.length&&ids.length)base=ids.map(x=>({event_id:x}))
  if(!base.length&&Array.isArray(inc.storyline))base=inc.storyline
  const seen=new Set()
  return base.map(item=>{
    const eid=item?.id??item?.event_id
    const full=fullById[String(eid)]||{}
    return {...item,...full,id:full.id??item.id??eid,event_id:item.event_id??full.id??eid}
  }).filter(item=>{const key=String(item.id??item.event_id??Math.random());if(seen.has(key))return false;seen.add(key);return true})
}

function Storyline({events,eventLookup={}}){return <div className="storyline-shell">{events.map((e,idx)=>{const eventId=e.event_id??e.id??'-';const actual=eventLookup[String(eventId)]||{};const stage=e.stage||e.stage_name||e.name||koEvent(e.event_type)||'SECURITY_EVENT';const desc=e.description||e.detail||koEvent(e.event_type)||'-';const file=e.file_name||actual.file_name||actual.file_path;const proc=e.process_name||actual.process_name;const detail=[desc,`Event #${eventId}`,fmt(e.timestamp||actual.timestamp||e.created_at),file?`파일 ${file}`:null,proc?`프로세스 ${proc}`:null].filter(Boolean).join(' · ');const risk=num(actual.risk_score??e.risk_score??e.event_risk_score);const level=actual.risk_level||e.risk_level||e.event_risk_level||'-';const mid=e.mitre_technique_id||e.mitre_technique||'';const mname=e.mitre_technique_name||'ATT&CK 미확정';const tactic=e.mitre_tactic||'Evidence Only';const conf=e.mitre_confidence||'NONE';return <React.Fragment key={`${eventId}-${idx}`}><div className="storyline-step"><div className="storyline-index">{String(idx+1).padStart(2,'0')}</div><div><div className="storyline-name">{stage}</div><div className="storyline-detail">{detail}</div><div className="mitre-row"><span>{mid?`${mid} · ${mname}`:mname}</span><span>{tactic}</span><span>근거 {conf}</span></div>{e.mitre_note&&<div className="storyline-detail">{e.mitre_note}</div>}</div><div className="storyline-risk"><b>{level}</b><br/>Risk {risk.toFixed(2)}</div></div>{idx<events.length-1&&<div className="storyline-arrow">↓</div>}</React.Fragment>})}</div>}

function PlaybookView({data,onAction}){if(!data)return <Notice>Playbook 데이터가 없습니다.</Notice>;const steps=arr(data,['steps','items','playbook_steps']),history=arr(data.history,['items']);const completed=num(data.completed_step_count,steps.filter(s=>['COMPLETED','SKIPPED'].includes(String(s.status).toUpperCase())).length);const total=num(data.total_step_count,steps.length);const progress=num(data.progress_percent,total?completed/total*100:0);return <><div className="playbook-shell"><div className="playbook-top"><div><div className="playbook-name">{data.playbook_name||data.name||data.title||'의심 활동 조사'}</div><div className="playbook-meta">Human approval required · {completed}/{total} 단계 완료</div></div><span className="playbook-status">{data.status||'PENDING'}</span></div><div className="playbook-progress-track"><div className="playbook-progress-fill" style={{width:`${Math.max(0,Math.min(progress,100))}%`}}/></div><div className="playbook-meta">진행률 {progress.toFixed(1)}% · {completed} / {total} 단계 처리</div></div>{steps.map((s,i)=>{const sid=s.step_id||s.id||`PB-${String(i+1).padStart(2,'0')}`;const st=String(s.status||'PENDING').toUpperCase();const approval=Boolean(s.approval_required??s.requires_approval);const approveDisabled=['APPROVED','COMPLETED','SKIPPED'].includes(st);const completeDisabled=['COMPLETED','SKIPPED'].includes(st)||(approval&&st!=='APPROVED');return <div className="playbook-step-wrap" key={sid}><div className="playbook-step-card"><div className="playbook-step-title">{sid} · {s.title||s.name||'대응 단계'}</div><div className="playbook-step-desc">{s.description||s.detail||''}</div><div className="playbook-badges"><span>{st}</span><span>{approval?'관리자 승인 필요':'조사/처리 단계'}</span><span>실제 시스템 자동 실행 없음</span></div></div><div className="playbook-step-actions">{approval&&<button className="btn primary small" disabled={approveDisabled} onClick={()=>onAction(s,'APPROVE')}>승인</button>}<button className="btn primary small" disabled={completeDisabled} onClick={()=>onAction(s,'COMPLETE')}>처리 완료</button></div></div>})}{history.length>0&&<><h4 className="subheading">대응 이력</h4>{[...history].slice(-10).reverse().map((h,i)=><div className="playbook-history" key={i}>{fmt(h.timestamp||h.created_at)} · <b>{({PLAYBOOK_CREATED:'Playbook 생성',STEP_APPROVED:'관리자 승인',STEP_COMPLETED:'처리 완료',STEP_SKIPPED:'단계 건너뜀'}[h.action]||h.action||h.status||'-')}</b> · {h.step_title||'Incident'}</div>)}</>}</>}

function unwrapAiResponse(response){
  if(response==null)return null
  let root=response
  if(typeof root==='string'){
    const trimmed=root.trim()
    if((trimmed.startsWith('{')&&trimmed.endsWith('}'))||(trimmed.startsWith('[')&&trimmed.endsWith(']'))){
      try{root=JSON.parse(trimmed)}catch{return root}
    }else return root
  }
  if(root&&typeof root==='object'&&root.ai_analysis!=null)root=root.ai_analysis
  if(typeof root==='string'){
    const trimmed=root.trim()
    if((trimmed.startsWith('{')&&trimmed.endsWith('}'))||(trimmed.startsWith('[')&&trimmed.endsWith(']'))){
      try{root=JSON.parse(trimmed)}catch{return root}
    }
  }
  return root
}

function AiList({items,numbered=false,prefix=''}) {
  const list=Array.isArray(items)?items:(items==null?[]:[items])
  if(!list.length)return <div className="ai-text">-</div>
  return numbered
    ? <ol className="ai-list numbered">{list.map((item,i)=><li key={i}>{objText(item)}</li>)}</ol>
    : <ul className="ai-list">{list.map((item,i)=><li key={i}>{prefix}{objText(item)}</li>)}</ul>
}

function EventAIReport({response}){
  const ai=unwrapAiResponse(response)
  if(!ai)return <Notice type="warning">AI 분석 응답은 받았지만 표시할 분석 내용이 없습니다.</Notice>
  if(typeof ai==='string')return <div className="ai-shell"><div className="ai-head"><div className="ai-title">AI 보안 사고 분석 보고서</div><div className="ai-model">LLM 보조 분석</div></div><div className="ai-text">{ai}</div></div>
  const summary=ai.summary??'분석 결과가 없습니다.'
  const scenario=ai.threat_scenario??'분석 결과가 없습니다.'
  const evidence=Array.isArray(ai.evidence)?ai.evidence:[]
  const recommendations=Array.isArray(ai.recommendations)?ai.recommendations:[]
  return <div className="ai-shell">
    <div className="ai-head"><div className="ai-title">AI 보안 사고 분석 보고서</div><div className="ai-model">LLM 보조 분석</div></div>
    <div className="ai-section-label">사고 요약</div>
    <div className="ai-text">{objText(summary)}</div>
    <div className="ai-section-label">의심 위협 시나리오</div>
    <div className="ai-text">{objText(scenario)}</div>
    {evidence.length>0&&<>
      <div className="ai-section-label">판단 근거</div>
      <div className="evidence-list">{evidence.map((item,index)=><div className="evidence-item" key={index}><div className="evidence-number">AI-{String(index+1).padStart(2,'0')}</div><div>{objText(item)}</div></div>)}</div>
    </>}
    {recommendations.length>0&&<>
      <div className="ai-section-label">대응 권고</div>
      {recommendations.map((item,index)=><div className="recommendation" key={index}><strong>{String(index+1).padStart(2,'0')}</strong>&nbsp;&nbsp;{objText(item)}</div>)}
    </>}
    {!evidence.length&&!recommendations.length&&summary==='분석 결과가 없습니다.'&&scenario==='분석 결과가 없습니다.'&&<details className="streamlit-expander"><summary>AI 원본 응답 보기</summary><pre className="ai-raw">{JSON.stringify(ai,null,2)}</pre></details>}
  </div>
}

function IncidentAIReport({response}){
  const ai=unwrapAiResponse(response)
  if(!ai)return <Notice type="warning">AI SOC 응답은 받았지만 표시할 분석 내용이 없습니다.</Notice>
  if(typeof ai==='string')return <div className="incident-ai-report"><h4>사고 요약</h4><Notice>{ai}</Notice></div>
  const mitre=Array.isArray(ai.mitre_analysis)?ai.mitre_analysis:[]
  const confirmed=Array.isArray(ai.confirmed_facts)?ai.confirmed_facts:[]
  const unknown=Array.isArray(ai.uncertainties)?ai.uncertainties:[]
  const evidence=Array.isArray(ai.key_evidence)?ai.key_evidence:[]
  const priorities=Array.isArray(ai.investigation_priorities)?ai.investigation_priorities:[]
  const recs=Array.isArray(ai.response_recommendations)?ai.response_recommendations:[]
  return <div className="incident-ai-report">
    <h4>사고 요약</h4>
    <Notice>{objText(ai.incident_summary??'-')}</Notice>
    <h4>가능한 위협 시나리오</h4>
    <div className="incident-ai-paragraph">{objText(ai.threat_scenario??'-')}</div>
    <div className="incident-ai-two-col">
      <div><h4>확인된 사실</h4><AiList items={confirmed}/></div>
      <div><h4>아직 확인되지 않은 사실</h4><AiList items={unknown}/></div>
    </div>
    <h4>공격 흐름 해석</h4>
    <div className="incident-ai-paragraph">{objText(ai.attack_flow_analysis??'-')}</div>
    {mitre.length>0&&<>
      <h4>MITRE ATT&CK 해석</h4>
      <div className="mitre-ai-list">{mitre.map((item,i)=><div key={i}><b>{item?.technique_id||'미확정'}</b> · {item?.interpretation||objText(item)}</div>)}</div>
    </>}
    <div className="incident-ai-two-col">
      <div>
        <h4>핵심 증거</h4><AiList items={evidence}/>
        <h4>우선 조사 항목</h4><AiList items={priorities} numbered/>
      </div>
      <div>
        <h4>대응 권고</h4><AiList items={recs} numbered/>
        <h4>분석가 주의사항</h4><Notice type="warning">{objText(ai.analyst_caution??'-')}</Notice>
      </div>
    </div>
    {!ai.incident_summary&&!ai.threat_scenario&&!confirmed.length&&!unknown.length&&!evidence.length&&!recs.length&&<details className="streamlit-expander"><summary>AI 원본 응답 보기</summary><pre className="ai-raw">{JSON.stringify(ai,null,2)}</pre></details>}
  </div>
}

function JsonNarrative({data}){
  const root=unwrapAiResponse(data)
  if(root==null)return null
  if(typeof root==='string')return <p className="ai-text">{root}</p>
  return <pre className="ai-raw">{JSON.stringify(root,null,2)}</pre>
}

function UserAnalysisPage({events,users,refresh}){
  const[form,setForm]=useState({username:'',display_name:'',department:'',role:''}),[msg,setMsg]=useState(''),[selected,setSelected]=useState(''),[profile,setProfile]=useState(null),[dyn,setDyn]=useState(null),[adaptive,setAdaptive]=useState(null),[busy,setBusy]=useState(false),[registerOpen,setRegisterOpen]=useState(false),[tableMode,setTableMode]=useState(false),[deleteConfirm,setDeleteConfirm]=useState({})
  useEffect(()=>{if(!selected&&users[0])setSelected(users[0].username||users[0].user)},[users])
  useEffect(()=>{if(!selected)return;api.behaviorProfile(selected).then(setProfile).catch(()=>setProfile(null));api.dynamicRisk(selected).then(setDyn).catch(()=>setDyn(null))},[selected])
  const create=async e=>{e.preventDefault();if(!form.username.trim())return;try{await api.createUser(form);setMsg(`${form.username.trim()} 사용자를 모니터링 대상으로 등록했습니다. 개인 행동 기준선 학습이 시작됩니다.`);setForm({username:'',display_name:'',department:'',role:''});setRegisterOpen(false);refresh()}catch(e){setMsg(`등록 실패: ${e.message}`)}}
  const toggle=async(u,en)=>{try{await api.setUserEnabled(u,en);refresh()}catch(e){setMsg(e.message)}}
  const remove=async u=>{if(!deleteConfirm[u])return;try{await api.deleteUser(u);setMsg('사용자를 삭제했습니다.');setDeleteConfirm(x=>({...x,[u]:false}));refresh()}catch(e){setMsg(e.message)}}
  const runAdaptive=async()=>{setBusy(true);try{setAdaptive(await api.adaptiveCompare())}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const userEvents=events.filter(e=>String(e.user)===String(selected));const userMax=Math.max(0,...userEvents.map(e=>num(e.risk_score))),userAvg=userEvents.length?userEvents.reduce((s,e)=>s+num(e.risk_score),0)/userEvents.length:0
  const enabledCount=users.filter(u=>Boolean(u.monitoring_enabled??u.enabled??u.is_enabled)).length;const learningCount=users.filter(u=>String(u.learning_status||'').toUpperCase()==='LEARNING').length
  return <><SectionHeader>모니터링 사용자 관리</SectionHeader><div className="kpis user-admin-kpis"><Kpi title="등록 사용자" value={users.length} hint="관리자가 등록한 모니터링 계정"/><Kpi title="활성 모니터링" value={enabledCount} hint="현재 이벤트 수집 허용 계정"/><Kpi title="기준선 학습 중" value={learningCount} hint="Adaptive Baseline LEARNING"/></div>
    <button className="streamlit-expander-button" onClick={()=>setRegisterOpen(v=>!v)}>› &nbsp; ＋ 모니터링 사용자 등록</button>{registerOpen&&<form className="register-expander" onSubmit={create}><div className="register-grid"><Field label="사용자명 *"><input placeholder="예: 김재경" value={form.username} onChange={e=>setForm({...form,username:e.target.value})}/></Field><Field label="부서"><input placeholder="예: IT" value={form.department} onChange={e=>setForm({...form,department:e.target.value})}/></Field><Field label="표시 이름"><input placeholder="예: 김재경" value={form.display_name} onChange={e=>setForm({...form,display_name:e.target.value})}/></Field><Field label="역할"><input placeholder="예: Developer" value={form.role} onChange={e=>setForm({...form,role:e.target.value})}/></Field></div><button className="btn primary register-submit">모니터링 사용자 등록</button></form>}{msg&&<Notice>{msg}</Notice>}
    <div className="section-caption">비활성화하면 새 /events 수집을 차단합니다. 삭제해도 기존 SecurityEvent 감사 이력은 보존됩니다.</div><div className="user-view-switch"><button className={`mini-btn ${!tableMode?'active-mini':''}`} onClick={()=>setTableMode(false)}>카드 보기</button><button className={`mini-btn ${tableMode?'active-mini':''}`} onClick={()=>setTableMode(true)}>표 보기</button></div>
    {!tableMode?<div className="monitored-user-list">{users.map((u,i)=>{const name=u.username||u.user||'-',display=u.display_name||name,enabled=Boolean(u.monitoring_enabled??u.enabled??u.is_enabled),ls=String(u.learning_status||'LEARNING').toUpperCase();return <div className="monitored-user-row" key={name}><div className="baseline-summary user-admin-card"><div className="baseline-top"><div><div className="baseline-user">{display}</div><div className="baseline-meta">계정 {name} · {u.department||'-'} · {u.role||'-'} · 정상 학습 {num(u.learning_event_count).toLocaleString()}개 · 가중치 {num(u.confidence_weight,.25).toFixed(2)}</div></div><span className="baseline-badge">{ls} · {enabled?'활성':'비활성'}</span></div></div><div className="user-control-stack"><button className="btn primary user-action-btn" onClick={()=>toggle(name,!enabled)}>{enabled?'비활성화':'활성화'}</button><label className="delete-confirm-inline"><input type="checkbox" checked={Boolean(deleteConfirm[name])} onChange={e=>setDeleteConfirm(x=>({...x,[name]:e.target.checked}))}/> 삭제 확인</label><button className="btn ghost user-delete-btn" disabled={!deleteConfirm[name]} onClick={()=>remove(name)}>삭제</button></div></div>})}</div>:<SimpleTable headers={['사용자','표시 이름','부서','역할','모니터링','학습 상태','관리']} rows={users.map(u=>{const name=u.username||u.user||'-',enabled=Boolean(u.monitoring_enabled??u.enabled??u.is_enabled);return [name,u.display_name||'-',u.department||'-',u.role||'-',enabled?'활성':'비활성',u.learning_status||'-',<span key={name}><button className="mini-btn" onClick={()=>toggle(name,!enabled)}>{enabled?'비활성':'활성'}</button><button className="mini-btn danger-mini" onClick={()=>setDeleteConfirm(x=>({...x,[name]:true}))}>삭제</button></span>]})}/>} 
    <SectionHeader>Adaptive Personal UEBA</SectionHeader><Field label="분석할 모니터링 사용자를 선택하세요."><select value={selected} onChange={e=>setSelected(e.target.value)}>{users.map(u=><option key={u.username||u.user} value={u.username||u.user}>{u.display_name||u.username||u.user}</option>)}</select></Field>{selected&&<><div className="baseline-summary"><div className="baseline-top"><div><div className="baseline-user">{users.find(u=>String(u.username||u.user)===String(selected))?.display_name||selected}</div><div className="baseline-meta">계정 {selected} · {users.find(u=>String(u.username||u.user)===String(selected))?.department||'-'} · {users.find(u=>String(u.username||u.user)===String(selected))?.role||'-'} · 모니터링 활성</div></div><span className="baseline-badge">BASELINE {profile?.confidence_level||profile?.learning_status||'-'}</span></div></div><SectionHeader>개인 행동 기준선 학습 상태</SectionHeader><ProfileView profile={profile} eventCount={userEvents.length}/><SectionHeader>Dynamic User Risk</SectionHeader><DynamicRiskView data={dyn} events={userEvents}/><SectionHeader>개별 이벤트 위험 지표</SectionHeader><div className="kpis compact"><Kpi title="전체 이벤트" value={userEvents.length} hint="수집된 사용자 활동"/><Kpi title="평균 Risk" value={userAvg.toFixed(1)} hint="사용자 평균 위험점수"/><Kpi title="최고 Risk" value={userMax.toFixed(1)} hint="관찰된 최고 위험도"/><Kpi title="고위험 이벤트" value={userEvents.filter(e=>['HIGH','CRITICAL'].includes(String(e.risk_level).toUpperCase())).length} hint="HIGH + CRITICAL"/></div><UserRiskAnalysis events={userEvents}/><SectionHeader>사용자 활동 이력</SectionHeader><EventTable events={userEvents.slice(0,100)} tall/></>}
    <SectionHeader>Adaptive Personal UEBA 비교 시연</SectionHeader><div className="adaptive-demo-shell teaser"><div className="adaptive-demo-head">동일 행동 · 서로 다른 개인 기준선</div><div className="adaptive-demo-sub">23:00 PowerShell 실행이라는 동일 행동을 일반 주간 사무직 사용자와 재택/유연근무 IT 사용자의 개인 기준선과 Adaptive 보정 결과로 비교합니다.</div></div><div className="adaptive-run-row"><button className="btn primary" disabled={busy} onClick={runAdaptive}>{busy?'비교 실행 중...':'Adaptive 비교 실행'}</button><div className="section-caption">고정 Rule은 두 사용자 모두 23시를 비정상 시간대로 판단하지만, 충분히 학습된 개인 정상 패턴과 일치하는 경우에만 시간 규칙의 기여도를 제한적으로 보정합니다.</div></div>{adaptive&&<AdaptiveCompare data={adaptive}/>}</>
}
function ProfileView({profile,eventCount=0}){
  if(!profile)return <Notice>Behavior Profile 데이터를 불러오는 중이거나 기준선이 아직 없습니다.</Notice>
  const confidence=String(profile.confidence_level||profile.learning_status||profile.status||'LEARNING').toUpperCase()
  const learningCount=num(profile.learning_event_count??profile.event_count)
  const weight=num(profile.confidence_weight)
  const pct=Math.max(0,Math.min(100,weight*100))
  const activeHours=Array.isArray(profile.active_hours)?(profile.active_hours.length?profile.active_hours.map(h=>`${String(Number(h)).padStart(2,'0')}시`).join(', '):'학습 데이터 부족'):(profile.active_hours||'학습 데이터 부족')
  const weekdayNames={0:'월',1:'화',2:'수',3:'목',4:'금',5:'토',6:'일'}
  const weekdays=Array.isArray(profile.active_weekdays)?(profile.active_weekdays.length?profile.active_weekdays.map(d=>weekdayNames[Number(d)]??d).join(', '):'학습 데이터 부족'):(profile.active_weekdays||'학습 데이터 부족')
  const ips=Array.isArray(profile.known_ips)?(profile.known_ips.length?profile.known_ips.join(', '):'학습 데이터 부족'):(profile.known_ips||'학습 데이터 부족')
  const processes=Array.isArray(profile.normal_processes)?(profile.normal_processes.length?profile.normal_processes.join(', '):'학습 데이터 부족'):(profile.normal_processes||'학습 데이터 부족')
  const avgFile=num(profile.average_file_access??profile.avg_file_access).toFixed(1)+'회'
  let usb=num(profile.usb_usage_rate); if(usb<=1)usb*=100
  return <>
    <div className="kpis baseline-status-grid"><Kpi title="학습 상태" value={confidence} hint="개인 기준선 신뢰도"/><Kpi title="정상 학습 이벤트" value={learningCount} hint="LOW 이벤트만 기준선 학습"/><Kpi title="기준선 가중치" value={weight.toFixed(2)} hint="학습량에 따른 탐지 반영도"/><Kpi title="현재 수집 이벤트" value={eventCount} hint="선택 사용자의 전체 이벤트"/></div>
    <div className="learning-note"><b>Learning Guard</b> · 현재 개인 행동 기준선은 이전 이벤트 중 <b>LOW 위험 등급</b>으로 판정된 정상 행동만 학습합니다. MEDIUM / HIGH / CRITICAL 이벤트는 감사 및 탐지 기록에는 유지되지만 정상 행동 기준에는 포함되지 않습니다.<div className="confidence-track"><div className="confidence-fill" style={{width:`${pct}%`}}/></div></div>
    <SectionHeader>학습된 정상 행동 프로필</SectionHeader>
    <div className="normal-profile-grid"><BaselineCard label="평소 활동 시간" value={activeHours} foot="개인별 시간대 패턴"/><BaselineCard label="평소 활동 요일" value={weekdays} foot="개인별 요일 패턴"/><BaselineCard label="알려진 Source IP" value={ips} foot="반복 관찰된 정상 접속지"/><BaselineCard label="정상 프로세스" value={processes} foot="반복 실행된 개인별 정상 프로세스"/><BaselineCard label="평균 파일 접근량" value={avgFile} foot="정상 행동의 평균 파일 접근"/><BaselineCard label="USB 사용률" value={`${usb.toFixed(1)}%`} foot="정상 학습 이벤트 기준"/></div>
  </>
}
function BaselineCard({label,value,foot}){return <div className="baseline-card"><div className="baseline-card-label">{label}</div><div className="baseline-card-value">{value}</div><div className="baseline-card-foot">{foot}</div></div>}
function DynamicRiskView({data,events=[]}){if(!data)return <Notice>Dynamic User Risk 데이터가 없습니다.</Notice>;const score=num(data.dynamic_risk_score??data.risk_score??data.score),level=data.risk_level||data.level||(score>=80?'CRITICAL':score>=60?'HIGH':score>=30?'MEDIUM':'LOW'),contributors=arr(data,['contributors','top_contributors','components']);const clusters=num(data.cluster_count??data.risk_cluster_count??contributors.length);return <><div className="dynamic-risk-shell"><div className="dynamic-risk-top"><div><div className="dynamic-risk-label">CURRENT USER STATE</div><div className="dynamic-risk-score">{score.toFixed(2)}</div><div className="dynamic-risk-meta">누적 사용자 위험 상태 · 최근 이벤트와 시간 감쇠 반영</div></div><span className={`dynamic-risk-badge ${riskClass(level)}`}>{level}</span></div><div className="dynamic-track"><div className="dynamic-fill" style={{width:`${Math.min(100,score)}%`}}/></div></div><div className="kpis compact dynamic-summary-kpis"><Kpi title="현재 User Risk" value={score.toFixed(2)} hint="개별 Event Risk와 분리된 사용자 상태"/><Kpi title="사용자 상태" value={level} hint="최근 위험 행동을 종합한 등급"/><Kpi title="위험 행동 군집" value={clusters} hint="MEDIUM 이상 10분 행동 군집"/><Kpi title="실제 기여 군집" value={contributors.length} hint="재평가 후 시간 감쇠 반영"/></div>{data.reason&&<div className="learning-note peer-note"><b>Dynamic Risk 해석</b> · {data.reason}</div>}<SectionHeader>Dynamic Risk 주요 기여 행동</SectionHeader>{contributors.length?<><div className="dynamic-contrib-layout"><ContributorTable items={contributors}/><ContributionBar items={contributors}/></div><SectionHeader>최근 위험 기여 행동 추이</SectionHeader><div className="section-caption">현재 API는 Dynamic User Risk의 과거 스냅샷을 별도 저장하지 않으므로, 현재 점수를 구성하는 위험 행동 군집의 시간별 기여도를 표시합니다.</div><ContributionLine items={contributors}/></>:<><Notice>최근 24시간 동안 Dynamic User Risk에 기여하는 MEDIUM 이상 행동 군집이 없습니다.</Notice><div className="section-caption">판정 근거 · 최근 24시간 내 MEDIUM 이상 사용자 위험 이벤트 없음</div></>}</>}
function ContributorTable({items}){return <SimpleTable headers={['시간','행동 유형','대표 Event Risk','Event Level','군집 이벤트','동일 유형 순번','유형 가중치','시간 감쇠','최종 기여도']} rows={items.map(c=>[fmt(c.timestamp),koEvent(c.event_type||c.type||c.name),num(c.risk_score??c.score).toFixed(2),c.risk_level||'-',c.cluster_event_count??0,c.same_type_occurrence??1,num(c.type_weight,1).toFixed(2),num(c.decay_weight,1).toFixed(3),num(c.weighted_score??c.contribution??c.score).toFixed(2)])}/>}
function ContributionBar({items}){const m={};items.forEach(c=>{const k=koEvent(c.event_type||c.type||c.name);m[k]=(m[k]||0)+num(c.weighted_score??c.contribution??c.score)});return <CategoryBar items={Object.entries(m).sort((a,b)=>b[1]-a[1])} title="행동 유형별 위험 기여도" sub="현재 Dynamic User Risk를 구성하는 행동 증거"/>}
function ContributionLine({items}){const rows=items.slice().sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp)).map(c=>({time:c.timestamp||c.created_at,y:num(c.weighted_score??c.contribution??c.score),label:fmt(c.timestamp||c.created_at)}));return <LineSvg rows={rows} xTitle="시간" yTitle="최종 기여도"/>}
function UserRiskAnalysis({events}){if(!events.length)return null;const levels=['CRITICAL','HIGH','MEDIUM','LOW'];const counts=levels.map(l=>[l,events.filter(e=>String(e.risk_level).toUpperCase()===l).length]);const tm={};events.forEach(e=>{const k=koEvent(e.event_type);tm[k]=(tm[k]||0)+1});const types=Object.entries(tm).sort((a,b)=>b[1]-a[1]);const riskRows=events.slice().sort((a,b)=>new Date(a.timestamp)-new Date(b.timestamp)).map(e=>({time:e.timestamp||e.created_at,y:num(e.risk_score),label:fmt(e.timestamp||e.created_at)}));return <><SectionHeader>사용자 위험도 분석</SectionHeader><div className="user-risk-analysis-grid"><SeverityPanel counts={counts}/><CategoryBar items={types} title="사용자 이벤트 유형" sub="선택 사용자의 이벤트 유형별 발생 건수"/></div><SectionHeader>개별 Event Risk 시간 추이</SectionHeader><div className="section-caption">개별 보안 이벤트의 Risk Score가 시간에 따라 어떻게 변화하는지 확인합니다. Dynamic User Risk와는 별도의 지표입니다. 시간 순서로 확인합니다.</div><LineSvg rows={riskRows} xTitle="시간" yTitle="Event Risk Score"/></>}
function SeverityPanel({counts}){const total=counts.reduce((s,x)=>s+x[1],0)||1;return <div className="mini-chart-card severity-panel"><div className="panel-title">위험 등급 현황</div><div className="panel-sub">전체 이벤트의 Risk Level 분포</div>{counts.map(([l,c])=>{const p=c/total*100;return <div className="severity-row-react" key={l}><b className={`sev-${l.toLowerCase()}`}>{l}</b><span>{c}</span><div className="sev-track"><div className={`sev-fill sev-${l.toLowerCase()}`} style={{width:`${c?Math.max(2.5,p):0}%`}}/></div><em>{p.toFixed(1)}%</em></div>})}</div>}
function CategoryBar({items,title,sub}){
  const labels=items.map(x=>String(x[0])),values=items.map(x=>num(x[1]))
  return <div className="mini-chart-card plotly-card"><div className="panel-title">{title}</div><div className="panel-sub">{sub}</div><PlotlyChart className="plotly-bar" data={[{type:'bar',x:labels,y:values,text:values.map(v=>Number.isInteger(v)?String(v):v.toFixed(2)),textposition:'outside',cliponaxis:false,hovertemplate:'<b>%{x}</b><br>값 %{y:.2f}<extra></extra>'}]} layout={{height:245,margin:{l:48,r:16,t:18,b:72},xaxis:{title:{text:'행동 유형',font:{size:10}},tickangle:-90,gridcolor:'#1b2532',zeroline:false},yaxis:{title:{text:'건수 / 기여도',font:{size:10}},gridcolor:'#25303d',zeroline:false},bargap:.35}}/></div>
}
function LineSvg({rows,yTitle='Risk Score',xTitle='시간'}){
  if(!rows.length)return <Notice>표시할 추이 데이터가 없습니다.</Notice>
  const x=rows.map(r=>r.time||r.label||r.x),y=rows.map(r=>num(r.y))
  return <div className="plotly-line-shell"><PlotlyChart className="plotly-line" data={[{type:'scatter',mode:'lines+markers',x,y,hovertemplate:`<b>${xTitle}</b> %{x}<br><b>${yTitle}</b> %{y:.2f}<extra></extra>`,line:{width:2},marker:{size:5}}]} layout={{height:320,margin:{l:60,r:20,t:18,b:58},xaxis:{title:{text:xTitle,font:{size:10}},type:'date',gridcolor:'#1b2532',showgrid:true,zeroline:false,rangeslider:{visible:false}},yaxis:{title:{text:yTitle,font:{size:10}},gridcolor:'#25303d',zeroline:false},dragmode:'zoom',hovermode:'x unified'}} config={{scrollZoom:true,displayModeBar:true}}/></div>
}

function AdaptiveCompare({data}){const office=data.office_demo||{},flex=data.flex_demo||{},same=data.same_behavior||{};return <div className="adaptive-demo-shell"><div className="adaptive-demo-head">동일 행동 · 서로 다른 개인 기준선</div><div className="adaptive-demo-sub">{same.description||objText(same)}</div><div className="adaptive-grid">{[[office,'office_demo','office'],[flex,'flex_demo','flex']].map(([x,name,cls])=><div className={`adaptive-demo-card adaptive-demo-${cls}`} key={name}><div className="adaptive-demo-type">{x.user_type||'-'}</div><div className="adaptive-demo-user">{name}</div><div className="adaptive-demo-row"><span>Baseline Score</span><b>{x.baseline_score??0}</b></div><div className="adaptive-demo-row"><span>개인 기준선 판정</span><b>{x.judgment||'-'}</b></div><div className="adaptive-demo-row"><span>Baseline 신뢰도</span><b>{x.confidence_level||'-'}</b></div><div className="adaptive-demo-row"><span>Adaptive 보정</span><b>-{num(x.adaptive_compensation)} · {x.adaptive_applied?'적용':'미적용'}</b></div><div className="adaptive-demo-reason">{arr(x.adaptive_reasons).join(' · ')||'-'}</div></div>)}</div>{data.comparison?.security_guard&&<Notice>{data.comparison.security_guard}</Notice>}</div>}

function BehaviorPage(){
  const[rows,setRows]=useState([]),[err,setErr]=useState(''),[status,setStatus]=useState('전체'),[user,setUser]=useState('전체'),[type,setType]=useState('전체'),[selected,setSelected]=useState(''),[note,setNote]=useState(''),[msg,setMsg]=useState('')
  const load=async()=>{
    try{
      const baseRaw=await api.behaviorChanges()
      const base=arr(baseRaw,['items','value','behavior_changes'])
      let userRows=[]
      try{
        const usersRaw=await api.users()
        userRows=arr(usersRaw,['items','value','users'])
      }catch{}
      const usernames=[...new Set([
        ...base.map(r=>r.user||r.username),
        ...userRows.map(r=>r.username||r.user)
      ].filter(Boolean))]
      const endpointProfiles=await Promise.all(
        usernames.map(async username=>{
          try{return await api.endpointProfile(username)}catch{return null}
        })
      )
      const endpointRows=endpointProfiles.flatMap(p=>
        arr(p?.observations).map(r=>({...r,user:p?.user||r.user}))
      )
      const merged=new Map()
      ;[...base,...endpointRows].forEach(r=>{
        const key=r.id!=null?`id:${r.id}`:`${r.user||r.username}|${r.change_type||r.type}|${r.change_value||r.value}`
        const prev=merged.get(key)||{}
        merged.set(key,{...prev,...r})
      })
      setRows([...merged.values()])
      setErr('')
    }catch(e){setErr(e.message)}
  };useEffect(()=>{load();const id=setInterval(load,5000);return()=>clearInterval(id)},[])
  const users=['전체',...new Set(rows.map(r=>r.user||r.username).filter(Boolean))],types=['전체',...new Set(rows.map(r=>r.change_type||r.type||r.category).filter(Boolean))],statuses=['전체','OBSERVING','ACCEPTED','REJECTED']
  const filtered=rows.filter(r=>(status==='전체'||String(r.status).toUpperCase()===status)&&(user==='전체'||String(r.user||r.username)===user)&&(type==='전체'||String(r.change_type||r.type||r.category)===type)).sort((a,b)=>num(b.id)-num(a.id))
  useEffect(()=>{if(!filtered.some(r=>String(r.id)===String(selected))&&filtered[0])setSelected(String(filtered[0].id))},[filtered.length,status,user,type])
  const row=filtered.find(r=>String(r.id)===String(selected))
  const decide=async action=>{if(!row)return;try{await api.behaviorDecision(row.id,action,note);setMsg(action==='approve'?'정상 행동으로 승인했습니다. Baseline 학습 허용 상태로 변경됩니다.':action==='reject'?'위험 행동으로 유지했습니다. 정상 Baseline 학습에서 제외됩니다.':'수동 판정을 해제하고 OBSERVING 상태로 되돌렸습니다.');setNote('');load()}catch(e){setMsg(e.message)}}
  const observing=rows.filter(r=>String(r.status).toUpperCase()==='OBSERVING').length,accepted=rows.filter(r=>String(r.status).toUpperCase()==='ACCEPTED').length,rejected=rows.filter(r=>String(r.status).toUpperCase()==='REJECTED').length,manual=rows.filter(r=>Boolean(r.manual_override)).length
  return <>
    <SectionHeader>Human-in-the-loop Behavior Review</SectionHeader><div className="section-caption">자동 UEBA가 OBSERVING 또는 REJECTED로 판정한 신규 행동을 SOC 관리자가 검토하고 정상 승인, 위험 유지 또는 재관찰로 수동 조정할 수 있습니다.</div>{err&&<Notice type="error">{err}</Notice>}
    <div className="st-metric-grid cols4 behavior-summary-metrics"><StMetric label="관찰 중" value={observing}/><StMetric label="정상 승인" value={accepted}/><StMetric label="학습 제외" value={rejected}/><StMetric label="관리자 수동 판정" value={manual}/></div><div className="section-caption">수동 승인 여부는 Behavior Change/Baseline 학습에만 반영되며 Rule · Sequence · Incident 탐지는 계속 동작합니다.</div>
    <SectionHeader>검토 대상 필터</SectionHeader><div className="filter-grid"><Field label="상태"><select value={status} onChange={e=>setStatus(e.target.value)}>{statuses.map(x=><option key={x}>{x}</option>)}</select></Field><Field label="사용자"><select value={user} onChange={e=>setUser(e.target.value)}>{users.map(x=><option key={x}>{x}</option>)}</select></Field><Field label="행동 유형"><select value={type} onChange={e=>setType(e.target.value)}>{types.map(x=><option key={x}>{x}</option>)}</select></Field></div>
    <SectionHeader>행동 변화 검토 목록</SectionHeader><SimpleTable short headers={['ID','사용자','유형','행동 값','상태','관찰 횟수','최대 Risk','수동 판정','최근 관찰']} rows={filtered.map(r=>[r.id,r.user||r.username||'-',r.change_type||r.type||r.category||'-',r.change_value||r.value||r.observed_value||r.process_name||r.ip_address||'-',r.status||'-',r.seen_count??r.observation_count??r.count??'-',num(r.max_risk_score||r.risk_score).toFixed(2),r.manual_override?'관리자':'자동',fmt(r.last_seen)])}/>
    <SectionHeader>SOC 관리자 판정</SectionHeader><Field label="검토할 행동 선택"><select value={selected} onChange={e=>setSelected(e.target.value)}>{filtered.map(r=><option key={r.id} value={r.id}>#{r.id} · {r.user||r.username} · {r.change_type||r.type||r.category}={r.change_value||r.value||r.observed_value||r.process_name||r.ip_address||'-'} · {r.status}</option>)}</select></Field>
    {row&&<><div className="behavior-decision-metrics st-metric-grid cols4"><StMetric label="현재 상태" value={row.status||'-'}/><StMetric label="관찰 횟수" value={row.seen_count??row.observation_count??row.count??'-'}/><StMetric label="최대 Risk" value={num(row.max_risk_score||row.risk_score).toFixed(2)}/><StMetric label="판정 주체" value={row.manual_override?'관리자':'자동 엔진'}/></div><div className="streamlit-bold">자동/수동 판정 사유</div><Notice>{row.decision_reason||row.reason||'-'}</Notice>{row.manual_note&&<div className="section-caption">기존 관리자 메모: {row.manual_note}</div>}<Field label="관리자 메모"><input value={note} onChange={e=>setNote(e.target.value)} placeholder="예: 정상적인 관리자 PowerShell 업무로 확인"/></Field><div className="action-row three"><button className="btn primary" onClick={()=>decide('approve')}>정상 승인 · Whitelist</button><button className="btn ghost" onClick={()=>decide('reject')}>위험 유지 · Reject</button><button className="btn ghost" onClick={()=>decide('reset')}>재관찰 · Reset</button></div>{msg&&<Notice>{msg}</Notice>}</>}
  </>
}
function Detail({label,value}){return <div className="detail-box"><div className="detail-label">{label}</div><div className="detail-value">{value??'-'}</div></div>}

function CertPage(){const thresholds=[[23.0,27.00,8.64,100],[23.5,22.08,7.35,100],[24.0,18.44,5.79,100],[24.5,'-',5.42,98.57],[25.0,'-',5.09,97.14],[26.0,'-',3.06,90],[27.0,'-',1.89,87.14],[30.0,3.68,.35,52.86]];return <><SectionHeader>평가 데이터 구성</SectionHeader><div className="section-caption">CERT Insider Threat Dataset r4.2에서 logon · device · file 이벤트를 공통 스키마로 변환하여 100,000건의 통제된 평가 샘플을 구성했습니다.</div><div className="st-metric-grid cols4"><StMetric label="평가 이벤트" value="100,000"/><StMetric label="악성 이벤트" value="2,993"/><StMetric label="정상 이벤트" value="97,007"/><StMetric label="탐지 Threshold" value="24"/></div><Notice>평가 샘플은 CERT 원본 분포 그대로가 아니라, 선택한 악성 이벤트 2,993건을 모두 포함하고 정상 이벤트를 무작위 샘플링한 통제된 100K 평가셋입니다.</Notice>
    <SectionHeader>Confusion Matrix</SectionHeader><SimpleTable headers={['실제 / 예측','위험 탐지','정상 판정']} rows={[['실제 악성',552,2441],['실제 정상',5619,91388]]}/><div className="st-metric-grid cols4 cert-gap"><StMetric label="TP" value="552" help="실제 악성 이벤트를 위험으로 탐지"/><StMetric label="FP" value="5,619" help="정상 이벤트를 위험으로 탐지"/><StMetric label="TN" value="91,388" help="정상 이벤트를 정상으로 판정"/><StMetric label="FN" value="2,441" help="악성 이벤트를 정상으로 판정"/></div>
    <SectionHeader>이벤트 단위 성능</SectionHeader><div className="st-metric-grid cols4"><StMetric label="Precision" value="8.95%"/><StMetric label="Recall" value="18.44%"/><StMetric label="False Positive Rate" value="5.79%"/><StMetric label="F1 Score" value="12.05%"/></div><Notice type="warning">이벤트 단위 Recall은 낮습니다. SENTINEL은 모든 하위 이벤트를 독립 경보로 발생시키기보다 의미 있는 위험 흐름과 핵심 이벤트를 선택적으로 탐지하도록 설계했습니다.</Notice>
    <SectionHeader>공격 시나리오 단위 탐지</SectionHeader><div className="st-metric-grid cols3"><StMetric label="전체 공격 시나리오" value="70"/><StMetric label="탐지 시나리오" value="70"/><StMetric label="Scenario Detection" value="100%"/></div><Notice type="success">Threshold 24 기준으로 각 CERT 공격 시나리오에서 최소 1개 이상의 라벨된 악성 이벤트가 탐지되어 70/70 시나리오를 식별했습니다.</Notice><div className="section-caption">※ 모든 악성 이벤트를 100% 탐지했다는 의미가 아니라 각 공격 시나리오에서 최소 1개 이상의 핵심 악성 이벤트를 탐지했다는 의미입니다.</div>
    <SectionHeader>Threshold 선택 근거</SectionHeader><SimpleTable headers={['Threshold','Recall (%)','FPR (%)','Scenario Detection (%)']} rows={thresholds}/><ThresholdChart rows={thresholds}/><div className="detail-panel"><h4>Threshold 24 선택 이유</h4><ul><li>24보다 높이면 오탐률은 더 감소하지만 공격 시나리오 탐지율이 떨어지기 시작합니다.</li><li>Threshold 24에서는 Scenario Detection 100%를 유지하면서 FPR을 5.79%까지 낮췄습니다.</li><li>따라서 공격 흐름 보존과 오탐 억제 사이의 균형점으로 24를 사용합니다.</li></ul></div>
    <SectionHeader>검증 결과 해석</SectionHeader><SimpleTable headers={['평가 관점','결과','해석']} rows={[['대규모 처리','100,000건 처리 완료','교수 피드백의 10만 건 이상 데이터 검증 조건 충족'],['이벤트 단위 탐지','Recall 18.44%','모든 악성 하위 이벤트를 개별 경보로 탐지하지는 않음'],['오탐','FPR 5.79%','탐지 민감도를 높인 만큼 일부 정상 이벤트 오탐 존재'],['공격 흐름 탐지','70/70 · 100%','모든 평가 공격 시나리오에서 최소 1개 이상의 핵심 악성 이벤트 탐지'],['향후 개선','Precision 8.95%','행동 기준선과 맥락 검증을 추가 학습하여 오탐을 더 줄일 필요']]}/><div className="chart-note">평가 기준 · CERT r4.2 통제 샘플 100,000건 · Threshold 24 · 이벤트 단위 및 시나리오 단위 평가 병행</div></>}
function ThresholdChart({rows}){const vals=rows.map(r=>({x:num(r[0]),f:num(r[2]),s:num(r[3])})),min=23,max=30;return <div className="threshold-chart"><div className="chart-y-label">%</div><svg viewBox="0 0 800 260" preserveAspectRatio="none"><polyline fill="none" stroke="#ef4444" strokeWidth="3" points={vals.map(v=>`${50+(v.x-min)/(max-min)*700},${230-v.f/100*200}`).join(' ')}/><polyline fill="none" stroke="#3b82f6" strokeWidth="3" points={vals.map(v=>`${50+(v.x-min)/(max-min)*700},${230-v.s/100*200}`).join(' ')}/>{vals.map(v=><g key={v.x}><circle cx={50+(v.x-min)/(max-min)*700} cy={230-v.s/100*200} r="4" fill="#3b82f6"/><text x={50+(v.x-min)/(max-min)*700} y="250" fill="#64748b" fontSize="12" textAnchor="middle">{v.x}</text></g>)}</svg><div className="chart-legend"><span><i className="blue"/>Scenario Detection</span><span><i className="red"/>FPR</span></div></div>}
function Footer(){return <div className="footer"><span>SENTINEL · 내부자 위협 탐지 및 대응 플랫폼</span><span>RULE · ML · UEBA · SEQUENCE · PII · LLM</span></div>}
