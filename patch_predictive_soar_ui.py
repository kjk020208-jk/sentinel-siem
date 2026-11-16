from pathlib import Path
import shutil
import sys

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'

if not APP.exists():
    print('[ERROR] App.jsx를 찾지 못했습니다.')
    print(r'프로젝트 루트 C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.')
    sys.exit(1)

backup = APP.with_name('App.before_prediction_ui.jsx')
if not backup.exists():
    shutil.copy2(APP, backup)
    print(f'[BACKUP] {backup.relative_to(ROOT)}')

app = APP.read_text(encoding='utf-8')
start = app.find('function SoarControlPage(){')
if start == -1:
    raise RuntimeError('SoarControlPage 시작 위치를 찾지 못했습니다.')
end = app.find('\nfunction BehaviorPage(){', start)
if end == -1:
    end = app.find('\nfunction CertPage(', start)
if end == -1:
    raise RuntimeError('SoarControlPage 끝 위치를 찾지 못했습니다.')

component = """function SoarControlPage(){
  const SOAR_API='https://api.sentineljk.co.kr'
  const[rows,setRows]=useState([])
  const[predictions,setPredictions]=useState([])
  const[err,setErr]=useState('')
  const[msg,setMsg]=useState('')
  const[busy,setBusy]=useState('')
  const[note,setNote]=useState('업무 필요성 및 증거 확인 후 관리자 승인')

  const call=async(path,options={})=>{
    const response=await fetch(`${SOAR_API}${path}`,{
      credentials:'include',
      ...options,
      headers:{
        ...(options.body?{'Content-Type':'application/json'}:{}),
        ...(options.headers||{})
      }
    })
    let data=null
    try{data=await response.json()}catch{}
    if(!response.ok)throw new Error(data?.detail||data?.message||`HTTP ${response.status}`)
    return data
  }

  const load=async()=>{
    try{
      const[controlData,predictionData]=await Promise.all([
        call('/response-controls?limit=100'),
        call('/threat-predictions?limit=100')
      ])
      setRows(arr(controlData,['items','value','response_controls']))
      setPredictions(arr(predictionData,['items','value','predictions','threat_predictions']))
      setErr('')
    }catch(e){setErr(e.message)}
  }

  useEffect(()=>{load();const id=setInterval(load,3000);return()=>clearInterval(id)},[])

  const decideRelease=async(id,decision)=>{
    if(!id||busy)return
    setBusy(`release:${id}:${decision}`);setMsg('')
    try{
      await call(`/response-controls/${id}/release-decision`,{method:'POST',body:JSON.stringify({decision,admin_note:note||null})})
      setMsg(decision==='APPROVE'?`해제 요청 #${id} 승인 완료 · RELEASE 작업이 Agent 큐에 등록되었습니다.`:`해제 요청 #${id} 거절 완료`)
      await load()
    }catch(e){setErr(e.message)}finally{setBusy('')}
  }

  const decidePrediction=async(id,decision)=>{
    if(!id||busy)return
    setBusy(`prediction:${id}:${decision}`);setMsg('')
    try{
      const result=await call(`/threat-predictions/${id}/decision`,{method:'POST',body:JSON.stringify({decision,admin_note:note||null})})
      const p=result?.prediction
      setMsg(decision==='APPROVE'?(p?.control_action_id?`Prediction #${id} 승인 · 실제 제어 #${p.control_action_id}가 SOAR 큐에 등록되었습니다.`:`Prediction #${id} 승인 완료`):`Prediction #${id} 거절 완료`)
      await load()
    }catch(e){setErr(e.message)}finally{setBusy('')}
  }

  const ordered=[...rows].sort((a,b)=>num(b.id)-num(a.id))
  const orderedPredictions=[...predictions].sort((a,b)=>num(b.id)-num(a.id))
  const awaiting=ordered.filter(r=>String(r.status||'').toUpperCase()==='AWAITING_ADMIN')
  const completed=ordered.filter(r=>String(r.status||'').toUpperCase()==='COMPLETED')
  const queued=ordered.filter(r=>['QUEUED','CLAIMED'].includes(String(r.status||'').toUpperCase()))
  const failed=ordered.filter(r=>String(r.status||'').toUpperCase()==='FAILED')
  const proposedPredictions=orderedPredictions.filter(p=>String(p.status||'').toUpperCase()==='PROPOSED')
  const automaticControls=ordered.filter(r=>String(r.requested_by||'').toUpperCase()==='PREDICTIVE_ENGINE')
  const latestPrediction=orderedPredictions[0]||null

  const statusKo=v=>({QUEUED:'대기',CLAIMED:'Agent 수신',COMPLETED:'실행 완료',FAILED:'실행 실패',AWAITING_ADMIN:'관리자 승인 대기',REJECTED:'거절',OBSERVING:'관찰',PROPOSED:'제어 제안',APPROVED:'승인',CONTROL_QUEUED:'제어 대기',CONTROL_FAILED:'제어 실패'}[String(v||'').toUpperCase()]||v||'-')
  const stageKo=v=>({NORMAL_ACTIVITY:'정상 활동',ACCESS_ATTEMPT:'접근 시도',ACCOUNT_ACCESS:'계정 접근',SENSITIVE_DATA_ACCESS:'민감정보 접근',DEVICE_PREPARATION:'장치 준비',EXFILTRATION_PREPARATION:'유출 준비'}[String(v||'').toUpperCase()]||v||'-')
  const responseLevelKo=v=>({OBSERVE:'관찰',ENHANCED_MONITORING:'감시 강화',PREPARE_CONTROL:'제어 준비',SELECTIVE_PREVENT:'선택적 선제 제어'}[String(v||'').toUpperCase()]||v||'-')
  const operationKo=v=>String(v||'').toUpperCase()==='RELEASE'?'해제':'적용'

  return <>
    <SectionHeader>Predictive Threat Progression</SectionHeader>
    <div className="section-caption">최근 사용자 행동의 순서와 Risk · Sequence · Personal/Peer UEBA 신호를 결합해 현재 위협 진행 단계와 다음 공격 벡터를 예측합니다. 조건이 충분히 충족되면 USB 유출 경로에 대해 선택적 Micro-Control을 수행할 수 있습니다.</div>

    {err&&<Notice type="error">SOAR / Prediction API 오류 · {err}</Notice>}
    {msg&&<Notice>{msg}</Notice>}

    <div className="st-metric-grid cols4">
      <StMetric label="현재 위협 단계" value={latestPrediction?stageKo(latestPrediction.current_stage):'-'} help={latestPrediction?.user||'Prediction 없음'}/>
      <StMetric label="Threat Progress" value={latestPrediction?`${latestPrediction.threat_progress??0}%`:'-'} help="공격 흐름 진행도"/>
      <StMetric label="Prediction Confidence" value={latestPrediction?`${latestPrediction.prediction_confidence??0}%`:'-'} help={latestPrediction?.predicted_vector||'다음 공격 벡터'}/>
      <StMetric label="자동 Micro-Control" value={latestPrediction?.auto_micro_control_enabled?'ON':'OFF'} help={`자동 제어 실행 ${automaticControls.length}건`}/>
    </div>

    {latestPrediction&&<>
      <SectionHeader>최신 예측 분석</SectionHeader>
      <div className="detail-grid related-detail-grid">
        <Detail label="사용자" value={latestPrediction.user||'-'}/><Detail label="대상 Host" value={latestPrediction.target_host||'-'}/><Detail label="현재 단계" value={stageKo(latestPrediction.current_stage)}/><Detail label="다음 공격 벡터" value={latestPrediction.predicted_vector||'-'}/><Detail label="대응 단계" value={responseLevelKo(latestPrediction.response_level)}/><Detail label="추천 제어" value={latestPrediction.recommended_control||'없음'}/><Detail label="Prediction 상태" value={statusKo(latestPrediction.status)}/><Detail label="연결된 제어 ID" value={latestPrediction.control_action_id?`#${latestPrediction.control_action_id}`:'-'}/>
      </div>
      <SectionHeader>예측 근거</SectionHeader>
      {arr(latestPrediction.evidence).length?<div className="evidence-list">{arr(latestPrediction.evidence).map((e,i)=><div className="evidence-item" key={`${latestPrediction.id}-${i}`}><div className="evidence-number">{String(i+1).padStart(2,'0')}</div><div>{e}</div></div>)}</div>:<Notice>현재 Prediction에 기록된 Evidence가 없습니다.</Notice>}
    </>}

    <SectionHeader>Prediction 제어 판단</SectionHeader>
    <div className="section-caption">자동 Micro-Control이 비활성화된 경우 고신뢰 Prediction은 제어 제안 상태로 남으며, 관리자가 승인하면 기존 Response Agent 큐에 실제 USB 쓰기 제한 작업이 생성됩니다.</div>
    <Field label="관리자 메모"><input value={note} onChange={e=>setNote(e.target.value)} placeholder="승인/거절 사유"/></Field>

    {proposedPredictions.length===0?<Notice>현재 관리자 판단을 기다리는 Prediction 제안이 없습니다.</Notice>:<div className="table-wrap"><table><thead><tr><th>ID</th><th>사용자</th><th>Host</th><th>현재 단계</th><th>진행도</th><th>다음 벡터</th><th>신뢰도</th><th>추천 제어</th><th>결정</th></tr></thead><tbody>{proposedPredictions.map(p=><tr key={p.id}><td>#{p.id}</td><td>{p.user||'-'}</td><td>{p.target_host||'-'}</td><td>{stageKo(p.current_stage)}</td><td>{p.threat_progress==null?'-':`${p.threat_progress}%`}</td><td>{p.predicted_vector||'-'}</td><td>{p.prediction_confidence==null?'-':`${p.prediction_confidence}%`}</td><td>{p.recommended_control||'-'}</td><td><div className="alert-actions"><button className="btn primary small" disabled={Boolean(busy)} onClick={()=>decidePrediction(p.id,'APPROVE')}>승인</button><button className="btn small" disabled={Boolean(busy)} onClick={()=>decidePrediction(p.id,'REJECT')}>거절</button></div></td></tr>)}</tbody></table></div>}

    <SectionHeader>Prediction 이력</SectionHeader>
    <SimpleTable tall headers={['ID','시각','사용자','Host','단계','진행도','예측 벡터','신뢰도','대응 단계','추천 제어','상태','제어 ID']} rows={orderedPredictions.map(p=>[`#${p.id}`,fmt(p.updated_at||p.created_at),p.user||'-',p.target_host||'-',stageKo(p.current_stage),p.threat_progress==null?'-':`${p.threat_progress}%`,p.predicted_vector||'-',p.prediction_confidence==null?'-':`${p.prediction_confidence}%`,responseLevelKo(p.response_level),p.recommended_control||'-',statusKo(p.status),p.control_action_id?`#${p.control_action_id}`:'-'])}/>

    <SectionHeader>실행형 SOAR 제어 현황</SectionHeader>
    <div className="section-caption">Prediction 또는 관리자 판단으로 생성된 제어 명령을 Windows Response Agent가 실제 엔드포인트에서 수행합니다. 현재 검증된 제어는 USB 쓰기 제한이며, 사용자는 해제를 요청하고 관리자는 롤백을 승인할 수 있습니다.</div>

    <div className="st-metric-grid cols4"><StMetric label="승인 대기" value={awaiting.length} help="사용자 해제 요청"/><StMetric label="실행 중" value={queued.length} help="QUEUED / CLAIMED"/><StMetric label="실행 완료" value={completed.length} help="실제 Agent 결과"/><StMetric label="실패" value={failed.length} help="FAILED"/></div>

    <SectionHeader>관리자 해제 승인</SectionHeader>
    {awaiting.length===0?<Notice>현재 관리자 승인을 기다리는 해제 요청이 없습니다.</Notice>:<div className="table-wrap"><table><thead><tr><th>ID</th><th>사용자</th><th>대상 Host</th><th>제어</th><th>요청 사유</th><th>Risk</th><th>예측 벡터</th><th>결정</th></tr></thead><tbody>{awaiting.map(r=><tr key={r.id}><td>#{r.id}</td><td>{r.user||'-'}</td><td>{r.target_host||'-'}</td><td>{operationKo(r.operation)} · {r.action_type||'-'}</td><td>{r.user_justification||r.reason||'-'}</td><td>{r.risk_score??'-'}</td><td>{r.predicted_vector||'-'}</td><td><div className="alert-actions"><button className="btn primary small" disabled={Boolean(busy)} onClick={()=>decideRelease(r.id,'APPROVE')}>승인</button><button className="btn small" disabled={Boolean(busy)} onClick={()=>decideRelease(r.id,'REJECT')}>거절</button></div></td></tr>)}</tbody></table></div>}

    <SectionHeader>실제 제어 이력</SectionHeader>
    <SimpleTable tall headers={['ID','시각','사용자','Host','동작','제어 유형','상태','Risk','진행도','예측 벡터','신뢰도','요청 주체','Agent 결과']} rows={ordered.map(r=>[`#${r.id}`,fmt(r.updated_at||r.completed_at||r.created_at),r.user||'-',r.target_host||'-',operationKo(r.operation),r.action_type||'-',statusKo(r.status),r.risk_score??'-',r.threat_progress==null?'-':`${r.threat_progress}%`,r.predicted_vector||'-',r.prediction_confidence==null?'-':`${r.prediction_confidence}%`,r.requested_by||'-',r.agent_message||'-'])}/>

    <div className="alert-actions"><button className="btn primary" onClick={load}>Prediction / SOAR 상태 새로고침</button></div>
  </>
}
"""

APP.write_text(app[:start] + component + app[end:], encoding='utf-8')
print('[PATCH] SoarControlPage -> Predictive SOAR UI 확장')
print('[DONE] Prediction + SOAR 통합 화면 적용')
print('다음: cd sentinel-react-frontend ; npm.cmd run build')
