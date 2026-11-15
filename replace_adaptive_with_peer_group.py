
from pathlib import Path
import re
import shutil
import sys

ROOT = Path.cwd()
MAIN = ROOT / "server" / "main.py"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

for p in (MAIN, APP):
    if not p.exists():
        print(f"[ERROR] 파일을 찾지 못했습니다: {p}")
        print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
        sys.exit(1)

shutil.copy2(MAIN, MAIN.with_name("main.before_peer_dashboard.py"))
shutil.copy2(APP, APP.with_name("App.before_peer_dashboard.jsx"))

main = MAIN.read_text(encoding="utf-8")
app = APP.read_text(encoding="utf-8")

# 1) behavior-profile endpoint에 Peer Group 분석 포함
behavior_start = main.find('@app.get("/users/{user}/behavior-profile")')
if behavior_start == -1:
    raise RuntimeError("behavior-profile endpoint를 찾지 못했습니다.")

next_route = main.find("\n@app.", behavior_start + 10)
if next_route == -1:
    next_route = len(main)

block = main[behavior_start:next_route]

if '_peer_group' not in block:
    return_pos = block.rfind("    return profile")
    if return_pos == -1:
        raise RuntimeError("behavior-profile의 return profile을 찾지 못했습니다.")

    peer_code = '''    # Dashboard Peer Group UEBA
    peer_profile = get_peer_group_profile(
        db=db,
        user=user
    )

    latest_event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user == user)
        .order_by(SecurityEvent.id.desc())
        .first()
    )

    peer_comparison = {
        "available": False,
        "applied": False,
        "score": 0,
        "reasons": [],
        "event_id": None,
        "event_type": None,
        "timestamp": None,
    }

    if latest_event is not None:
        peer_result = analyze_peer_group_baseline(
            db=db,
            user=user,
            current_ip=latest_event.source_ip,
            current_hour=(
                latest_event.timestamp.hour
                if latest_event.timestamp is not None
                else datetime.now().hour
            ),
            current_file_access_count=(
                latest_event.file_access_count or 0
            ),
            current_process_name=latest_event.process_name,
            current_usb_connected=(
                latest_event.usb_connected or 0
            ),
            current_timestamp=(
                latest_event.timestamp or datetime.now()
            ),
        )

        peer_comparison = {
            **peer_result,
            "event_id": latest_event.id,
            "event_type": latest_event.event_type,
            "timestamp": latest_event.timestamp,
            "process_name": latest_event.process_name,
            "source_ip": latest_event.source_ip,
            "file_access_count": (
                latest_event.file_access_count or 0
            ),
            "usb_connected": (
                latest_event.usb_connected or 0
            ),
        }

    profile["_peer_group"] = {
        **peer_profile,
        "latest_comparison": peer_comparison,
    }

'''
    block = block[:return_pos] + peer_code + block[return_pos:]
    main = main[:behavior_start] + block + main[next_route:]

# 2) frontend state / old handler cleanup
app = app.replace(
    ",[adaptive,setAdaptive]=useState(null),[busy,setBusy]=useState(false)",
    "",
    1,
)

app = re.sub(
    r"\n\s*const runAdaptive=async\(\)=>\{.*?\}\n",
    "\n",
    app,
    count=1,
)

# 3) replace AdaptiveCompare component with PeerGroupView
peer_component = r'''function PeerGroupView({profile}){
  const peer=profile?._peer_group||{}
  const comparison=peer?.latest_comparison||{}
  const available=Boolean(peer?.available)
  const applied=Boolean(comparison?.applied)
  const peerUsers=arr(peer?.peer_users)
  const personalHours=arr(profile?.active_hours)
  const peerHours=arr(peer?.active_hours)
  const personalProcesses=arr(profile?.normal_processes)
  const peerProcesses=arr(peer?.normal_processes)

  const fmtHours=v=>v.length
    ? v.map(h=>`${String(Number(h)).padStart(2,'0')}시`).join(', ')
    : '데이터 없음'

  const fmtList=v=>v.length?v.join(', '):'데이터 없음'

  const personalFile=num(
    profile?.average_file_access??profile?.avg_file_access
  ).toFixed(1)

  const peerFile=num(peer?.average_file_access).toFixed(1)

  let personalUsb=num(profile?.usb_usage_rate)
  if(personalUsb<=1)personalUsb*=100

  const peerUsb=num(peer?.usb_usage_rate_percent)

  const score=num(comparison?.score)
  const judgment=!available
    ? 'PEER 학습 부족'
    : !applied
      ? '비교 보류'
      : score>=60
        ? '동일 직무 대비 큰 이탈'
        : score>=30
          ? '동일 직무 대비 주의'
          : score>0
            ? '동일 직무 대비 경미한 차이'
            : '동일 직무 정상 범위'

  return <>
    <div className="baseline-summary">
      <div className="baseline-top">
        <div>
          <div className="baseline-user">Peer Group UEBA</div>
          <div className="baseline-meta">
            같은 부서 + 같은 역할의 활성 사용자와 비교 · 본인 제외
          </div>
        </div>
        <span className="baseline-badge">
          {available?'PEER READY':'PEER LEARNING'}
        </span>
      </div>
    </div>

    <div className="kpis compact">
      <Kpi
        title="Peer Group"
        value={peer?.group_key||'-'}
        hint="Department / Role"
      />
      <Kpi
        title="Peer 사용자"
        value={num(peer?.peer_user_count)}
        hint={`최소 ${num(peer?.minimum_peer_users,2)}명 필요`}
      />
      <Kpi
        title="Peer 학습 이벤트"
        value={num(peer?.peer_event_count).toLocaleString()}
        hint={`LOW 정상 이벤트 · 최소 ${num(peer?.minimum_peer_events,20)}건`}
      />
      <Kpi
        title="Peer Group Score"
        value={score.toFixed(1)}
        hint={judgment}
      />
    </div>

    {!available&&
      <Notice type="warning">
        동일 부서·역할의 Peer가 충분하지 않아 Peer Group 점수를 적용하지 않습니다.
        현재 비교 대상: {peerUsers.length?peerUsers.join(', '):'없음'}
      </Notice>
    }

    {available&&<>
      <div className="section-caption">
        비교 대상 · {peerUsers.join(', ')}
      </div>

      <div className="normal-profile-grid">
        <BaselineCard
          label="활동 시간 · 개인"
          value={fmtHours(personalHours)}
          foot="선택 사용자의 정상 시간 패턴"
        />
        <BaselineCard
          label="활동 시간 · Peer"
          value={fmtHours(peerHours)}
          foot="동일 직무 그룹의 정상 시간 패턴"
        />
        <BaselineCard
          label="정상 프로세스 · 개인"
          value={fmtList(personalProcesses)}
          foot="선택 사용자의 반복 정상 프로세스"
        />
        <BaselineCard
          label="정상 프로세스 · Peer"
          value={fmtList(peerProcesses)}
          foot="동일 직무 그룹의 반복 정상 프로세스"
        />
        <BaselineCard
          label="평균 파일 접근 · 개인"
          value={`${personalFile}회`}
          foot="개인 정상 기준"
        />
        <BaselineCard
          label="평균 파일 접근 · Peer"
          value={`${peerFile}회`}
          foot="동일 직무 그룹 정상 기준"
        />
        <BaselineCard
          label="USB 사용률 · 개인"
          value={`${personalUsb.toFixed(1)}%`}
          foot="개인 LOW 학습 이벤트 기준"
        />
        <BaselineCard
          label="USB 사용률 · Peer"
          value={`${peerUsb.toFixed(1)}%`}
          foot="Peer LOW 학습 이벤트 기준"
        />
      </div>

      <SectionHeader>최신 이벤트 Peer Group 판정</SectionHeader>
      <div className="kpis compact">
        <Kpi
          title="비교 Event"
          value={comparison?.event_id??'-'}
          hint={koEvent(comparison?.event_type)}
        />
        <Kpi
          title="Peer Score"
          value={score.toFixed(1)}
          hint="동일 직무 정상 패턴 이탈 점수"
        />
        <Kpi
          title="적용 상태"
          value={applied?'APPLIED':'NOT APPLIED'}
          hint="Peer Group UEBA 적용 여부"
        />
        <Kpi
          title="판정"
          value={judgment}
          hint="동일 직무 사용자 대비"
        />
      </div>

      <Notice type={score>=30?'warning':'success'}>
        {arr(comparison?.reasons).length
          ? arr(comparison?.reasons).join(' · ')
          : '동일 직무 Peer Group 정상 패턴과 비교할 추가 이탈 근거가 없습니다.'}
      </Notice>
    </>}
  </>
}

'''

adaptive_start = app.find("function AdaptiveCompare(")
behavior_page_start = app.find("\nfunction BehaviorPage()", adaptive_start)

if adaptive_start != -1 and behavior_page_start != -1:
    app = app[:adaptive_start] + peer_component + app[behavior_page_start+1:]
elif "function PeerGroupView(" not in app:
    raise RuntimeError("AdaptiveCompare 컴포넌트 교체 위치를 찾지 못했습니다.")

# 4) replace old demo section
old_pattern = re.compile(
    r'<SectionHeader>Adaptive Personal UEBA 비교 시연</SectionHeader>'
    r'.*?\{adaptive&&<AdaptiveCompare data=\{adaptive\}/>\}',
    re.S,
)

replacement = (
    '<SectionHeader>Peer Group UEBA · 동일 직무 비교</SectionHeader>'
    '<div className="section-caption">'
    '선택 사용자를 같은 부서·같은 역할의 활성 모니터링 사용자들과 비교합니다. '
    '개인 기준선과 Peer Group 기준선을 함께 사용해 개인에게는 익숙하지만 '
    '동일 직무 집단에서는 드문 행동도 확인합니다.'
    '</div>'
    '<PeerGroupView profile={profile}/>'
)

app, n = old_pattern.subn(replacement, app, count=1)

if n != 1 and "Peer Group UEBA · 동일 직무 비교" not in app:
    raise RuntimeError("기존 Adaptive 비교 섹션 자동 교체에 실패했습니다.")

MAIN.write_text(main, encoding="utf-8")
APP.write_text(app, encoding="utf-8")

print("")
print("=" * 76)
print("SENTINEL Peer Group Dashboard patch 완료")
print("=" * 76)
print("- office_demo / flex_demo 비교 UI 제거")
print("- 별도 비교용 이벤트 생성 없음")
print("- 선택 사용자 기준 실제 department + role Peer Group 사용")
print("- Peer 사용자 / 학습 이벤트 / 시간 / 프로세스 / 파일 / USB 비교")
print("- 최신 실제 이벤트의 Peer Group Score 및 판정 표시")
print("- api.js 수정 없음")
print("")
print("다음:")
print("python -m py_compile server/main.py")
print("cd sentinel-react-frontend")
print("npm.cmd run build")
