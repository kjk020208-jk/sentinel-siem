
from pathlib import Path
import re
import shutil
import sys

ROOT = Path.cwd()
MAIN = ROOT / "server" / "main.py"
BASELINE = ROOT / "server" / "baseline_engine.py"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
API = ROOT / "sentinel-react-frontend" / "src" / "api.js"

required = [MAIN, BASELINE, APP, API]
missing = [str(p) for p in required if not p.exists()]
if missing:
    print("[ERROR] 필요한 파일이 없습니다.")
    for p in missing:
        print(" -", p)
    print(r"프로젝트 루트 C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
    sys.exit(1)

for path in required:
    shutil.copy2(
        path,
        path.with_name(path.name + ".before_exhibition_all_fix")
    )

main = MAIN.read_text(encoding="utf-8")
baseline = BASELINE.read_text(encoding="utf-8")
app = APP.read_text(encoding="utf-8")
api = API.read_text(encoding="utf-8")

# ============================================================
# 1) server/main.py
# ============================================================

if "from datetime import datetime, timedelta" not in main:
    main = main.replace(
        "from datetime import datetime",
        "from datetime import datetime, timedelta",
        1,
    )

# --- /events/summary ------------------------------------------------
if '@app.get("/events/summary")' not in main:
    anchor = '@app.get("/events")\ndef get_events('
    if anchor not in main:
        raise RuntimeError("server/main.py에서 /events endpoint를 찾지 못했습니다.")

    endpoint = '''
@app.get("/events/summary")
def get_event_summary(
    db: Session = Depends(get_db)
):
    active_users = [
        str(row[0])
        for row in (
            db.query(MonitoredUser.username)
            .filter(MonitoredUser.monitoring_enabled == 1)
            .all()
        )
        if row[0]
    ]

    if not active_users:
        return {
            "total_events": 0,
            "anomalies": 0,
            "high_risk": 0,
            "critical": 0,
            "active_users": 0,
        }

    base = db.query(SecurityEvent).filter(
        SecurityEvent.user.in_(active_users)
    )

    return {
        "total_events": int(base.count()),
        "anomalies": int(
            base.filter(
                SecurityEvent.anomaly_score >= 50
            ).count()
        ),
        "high_risk": int(
            base.filter(
                SecurityEvent.risk_level.in_(
                    ["HIGH", "CRITICAL"]
                )
            ).count()
        ),
        "critical": int(
            base.filter(
                SecurityEvent.risk_level == "CRITICAL"
            ).count()
        ),
        "active_users": int(len(active_users)),
    }


'''
    main = main.replace(anchor, endpoint + anchor, 1)

# --- lightweight /users ---------------------------------------------
users_re = re.compile(
    r'@app\.get\("/users"\)\n'
    r'def get_monitored_users\(db: Session = Depends\(get_db\)\):\n'
    r'.*?'
    r'(?=\n@app\.get\("/users/\{username\}"\))',
    re.S,
)

new_users = '''@app.get("/users")
def get_monitored_users(
    db: Session = Depends(get_db)
):
    users = (
        db.query(MonitoredUser)
        .order_by(MonitoredUser.id.asc())
        .all()
    )

    now = datetime.now()
    since = now - timedelta(days=30)
    results = []

    for monitored_user in users:
        learning_count = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user == monitored_user.username,
                SecurityEvent.timestamp >= since,
                SecurityEvent.timestamp < now,
                SecurityEvent.risk_level == "LOW",
            )
            .count()
        )

        if learning_count < 20:
            learning_status = "LEARNING"
            confidence_weight = 0.25
        elif learning_count < 50:
            learning_status = "LOW"
            confidence_weight = 0.50
        elif learning_count < 100:
            learning_status = "MEDIUM"
            confidence_weight = 0.75
        else:
            learning_status = "HIGH"
            confidence_weight = 1.00

        results.append({
            "id": monitored_user.id,
            "username": monitored_user.username,
            "display_name": monitored_user.display_name,
            "department": monitored_user.department,
            "role": monitored_user.role,
            "monitoring_enabled": bool(
                monitored_user.monitoring_enabled
            ),
            "created_at": monitored_user.created_at,
            "learning_status": learning_status,
            "learning_event_count": int(learning_count),
            "confidence_weight": confidence_weight,
        })

    return results

'''

if users_re.search(main):
    main = users_re.sub(new_users, main, count=1)
elif "learning_count = (" not in main:
    raise RuntimeError("/users endpoint 자동 교체에 실패했습니다.")

# --- /users/{username}/events ---------------------------------------
if '@app.get("/users/{username}/events")' not in main:
    anchor = '@app.get("/users/{username}")'
    if anchor not in main:
        raise RuntimeError("/users/{username} endpoint 위치를 찾지 못했습니다.")

    endpoint = '''
@app.get("/users/{username}/events")
def get_user_events(
    username: str,
    limit: int = 1000,
    db: Session = Depends(get_db),
):
    monitored_user = (
        db.query(MonitoredUser)
        .filter(
            MonitoredUser.username == username
        )
        .first()
    )

    if not monitored_user:
        raise HTTPException(
            status_code=404,
            detail="등록된 사용자를 찾을 수 없습니다.",
        )

    safe_limit = max(
        1,
        min(int(limit or 1000), 5000),
    )

    query = db.query(SecurityEvent).filter(
        SecurityEvent.user == username
    )

    total_count = int(query.count())

    events = (
        query
        .order_by(SecurityEvent.id.desc())
        .limit(safe_limit)
        .all()
    )

    return {
        "username": username,
        "total_count": total_count,
        "events": events,
    }


'''
    main = main.replace(anchor, endpoint + anchor, 1)

# ============================================================
# 2) baseline_engine.py
# ============================================================

if "exhibition_history_exists" not in baseline:
    old = '''    if (
        monitored_user is not None
        and monitored_user.created_at is not None
        and monitored_user.created_at > learning_since
    ):
        learning_since = monitored_user.created_at
'''

    new = '''    exhibition_history_exists = (
        db.query(SecurityEvent.id)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.source.like("exhibition_seed%")
        )
        .first()
        is not None
    )

    if (
        not exhibition_history_exists
        and monitored_user is not None
        and monitored_user.created_at is not None
        and monitored_user.created_at > learning_since
    ):
        learning_since = monitored_user.created_at
'''

    if old not in baseline:
        raise RuntimeError("baseline_engine.py 등록 시점 보호 로직을 찾지 못했습니다.")

    baseline = baseline.replace(old, new, 1)

# ============================================================
# 3) api.js
# ============================================================

def add_api_clone(source, src_key, new_key, old_path_pattern, new_path):
    if re.search(rf'\b{re.escape(new_key)}\s*:', source):
        return source

    lines = source.splitlines()

    for idx, line in enumerate(lines):
        if (
            re.search(rf'\b{re.escape(src_key)}\s*:', line)
            and re.search(old_path_pattern, line)
        ):
            cloned = re.sub(
                rf'\b{re.escape(src_key)}\s*:',
                f'{new_key}:',
                line,
                count=1,
            )
            cloned = re.sub(
                old_path_pattern,
                lambda m: m.group(1) + new_path + m.group(1),
                cloned,
                count=1,
            )
            lines.insert(idx + 1, cloned)
            return "\n".join(lines) + ("\n" if source.endswith("\n") else "")

    raise RuntimeError(f"api.js에서 {src_key} 항목을 찾지 못했습니다.")

api = add_api_clone(
    api,
    "events",
    "eventSummary",
    r'(["\'])/events(?:\?[^"\']*)?\1',
    "/events/summary",
)

if not re.search(r'\buserEvents\s*:', api):
    lines = api.splitlines()
    inserted = False

    for idx, line in enumerate(lines):
        if re.search(r'\bbehaviorProfile\s*:', line):
            helper_match = re.search(
                r'=>\s*([A-Za-z_$][A-Za-z0-9_$]*)\(',
                line,
            )
            helper = helper_match.group(1) if helper_match else None

            param_match = re.search(
                r'behaviorProfile\s*:\s*\(?\s*([A-Za-z_$][A-Za-z0-9_$]*)',
                line,
            )
            param = param_match.group(1) if param_match else "username"

            if helper:
                indent = re.match(r'\s*', line).group(0)
                new_line = (
                    indent
                    + f"userEvents:({param})=>{helper}(`/users/${{{param}}}/events?limit=1000`),"
                )
                lines.insert(idx + 1, new_line)
                api = "\n".join(lines) + ("\n" if api.endswith("\n") else "")
                inserted = True
                break

    if not inserted:
        raise RuntimeError("api.js에 userEvents API를 자동 추가하지 못했습니다.")

# ============================================================
# 4) App.jsx
# ============================================================

# summary polling
if "eventSummaryRaw" not in app:
    target = (
        "  const [eventsRaw,eventsErr,,eventsLatency]="
        "usePolling(api.events,autoRefresh?3000:86400000,refreshKey)"
    )
    if target not in app:
        raise RuntimeError("App.jsx events polling 구문을 찾지 못했습니다.")

    replacement = (
        target
        + "\n"
        + "  const [eventSummaryRaw]="
          "usePolling(api.eventSummary,autoRefresh?3000:86400000,refreshKey)"
    )
    app = app.replace(target, replacement, 1)

# props
app = app.replace(
    "<OverviewV2 events={events} users={users} latestIncident={latestIncident}",
    "<OverviewV2 events={events} users={users} summary={eventSummaryRaw} latestIncident={latestIncident}",
)
app = app.replace(
    "<EventsPage events={events}/>",
    "<EventsPage events={events} monitoredUsers={users} summary={eventSummaryRaw}/>",
)
app = app.replace(
    "<UserAnalysisPage events={events} users={users} refresh={refresh}/>",
    "<UserAnalysisPage users={users} refresh={refresh}/>",
)

# Overview V2
app = app.replace(
    "function OverviewV2({events,users,latestIncident,setPage,error,latency})",
    "function OverviewV2({events,users,summary,latestIncident,setPage,error,latency})",
)
app = app.replace(
    "<strong>{events.length.toLocaleString()}</strong>",
    "<strong>{num(summary?.total_events,events.length).toLocaleString()}</strong>",
    1,
)
app = app.replace(
    "<strong>{anomaly.toLocaleString()}</strong>",
    "<strong>{num(summary?.anomalies,anomaly).toLocaleString()}</strong>",
    1,
)
app = app.replace(
    "{highCritical.toLocaleString()}",
    "{num(summary?.high_risk,highCritical).toLocaleString()}",
    1,
)
app = app.replace(
    "<strong>{enabledUsers.toLocaleString()}</strong>",
    "<strong>{num(summary?.active_users,enabledUsers).toLocaleString()}</strong>",
    1,
)

# EventsPage
app = app.replace(
    "function EventsPage({events}){",
    "function EventsPage({events,monitoredUsers=[],summary}){",
    1,
)

old_lists = "  const levels=['전체',...new Set(events.map(e=>e.risk_level).filter(Boolean))],users=['전체',...new Set(events.map(e=>e.user).filter(Boolean))],types=['전체',...new Set(events.map(e=>koEvent(e.event_type)).filter(Boolean))]"
new_lists = '''  const levels=['전체',...new Set(events.map(e=>e.risk_level).filter(Boolean))]
  const monitoredUserNames=monitoredUsers
    .filter(u=>u.monitoring_enabled===true||u.enabled===true||u.is_enabled===true)
    .map(u=>String(u.username||u.user||''))
    .filter(Boolean)
  const users=['전체',...new Set(monitoredUserNames.length?monitoredUserNames:events.map(e=>e.user).filter(Boolean))]
  const types=['전체',...new Set(events.map(e=>koEvent(e.event_type)).filter(Boolean))]'''

if old_lists in app:
    app = app.replace(old_lists, new_lists, 1)

if "const hasEventFilter=" not in app:
    marker = "  const filtered=events.filter("
    start = app.find(marker)
    if start == -1:
        raise RuntimeError("EventsPage filtered 구문을 찾지 못했습니다.")

    end = app.find("\n", start)
    if end == -1:
        raise RuntimeError("EventsPage filtered 줄 끝을 찾지 못했습니다.")

    helpers = '''
  const hasEventFilter=
    level!=='전체'||
    user!=='전체'||
    type!=='전체'||
    Boolean(search.trim())

  const visibleEventCount=hasEventFilter
    ? filtered.length
    : num(summary?.total_events,filtered.length)

  const visibleCritical=hasEventFilter
    ? filtered.filter(e=>String(e.risk_level).toUpperCase()==='CRITICAL').length
    : num(summary?.critical,0)

  const visibleHigh=hasEventFilter
    ? filtered.filter(e=>String(e.risk_level).toUpperCase()==='HIGH').length
    : Math.max(0,num(summary?.high_risk,0)-num(summary?.critical,0))

  const visibleUsers=hasEventFilter
    ? new Set(filtered.map(e=>e.user).filter(Boolean)).size
    : num(
        summary?.active_users,
        monitoredUserNames.length||
        new Set(filtered.map(e=>e.user).filter(Boolean)).size
      )
'''
    app = app[:end+1] + helpers + app[end+1:]

old_kpi_fragment = '<Kpi title="조회 이벤트" value={filtered.length} hint="현재 필터 조건"/>'
if old_kpi_fragment in app:
    app = app.replace(
        old_kpi_fragment,
        '<Kpi title="조회 이벤트" value={visibleEventCount.toLocaleString()} hint={hasEventFilter?\'현재 로딩 구간의 필터 결과\':\'전체 모니터링 이벤트\'}/>',
        1,
    )

app = app.replace(
    '<Kpi title="CRITICAL" value={filtered.filter(e=>e.risk_level===\'CRITICAL\').length} hint="긴급 위험 이벤트" danger/>',
    '<Kpi title="CRITICAL" value={visibleCritical.toLocaleString()} hint="긴급 위험 이벤트" danger/>',
    1,
)
app = app.replace(
    '<Kpi title="HIGH" value={filtered.filter(e=>e.risk_level===\'HIGH\').length} hint="고위험 이벤트" warning/>',
    '<Kpi title="HIGH" value={visibleHigh.toLocaleString()} hint="고위험 이벤트" warning/>',
    1,
)
app = app.replace(
    '<Kpi title="사용자" value={new Set(filtered.map(e=>e.user).filter(Boolean)).size} hint="조회된 사용자"/>',
    '<Kpi title="사용자" value={visibleUsers.toLocaleString()} hint={hasEventFilter?\'현재 필터 결과 사용자\':\'활성 모니터링 사용자\'}/>',
    1,
)

# UserAnalysisPage
app = app.replace(
    "function UserAnalysisPage({events,users,refresh}){",
    "function UserAnalysisPage({users,refresh}){",
    1,
)

if "selectedUserEvents" not in app:
    target = "[deleteConfirm,setDeleteConfirm]=useState({})"
    if target not in app:
        raise RuntimeError("UserAnalysisPage state 끝을 찾지 못했습니다.")
    app = app.replace(
        target,
        target
        + ",[selectedUserEvents,setSelectedUserEvents]=useState([])"
        + ",[selectedUserEventTotal,setSelectedUserEventTotal]=useState(0)"
        + ",[userEventError,setUserEventError]=useState('')",
        1,
    )

old_effect = "  useEffect(()=>{if(!selected)return;api.behaviorProfile(selected).then(setProfile).catch(()=>setProfile(null));api.dynamicRisk(selected).then(setDyn).catch(()=>setDyn(null))},[selected])"
new_effect = '''  useEffect(()=>{
    if(!selected)return
    let active=true

    setProfile(null)
    setDyn(null)
    setSelectedUserEvents([])
    setSelectedUserEventTotal(0)
    setUserEventError('')

    Promise.allSettled([
      api.behaviorProfile(selected),
      api.dynamicRisk(selected),
      api.userEvents(selected),
    ]).then(results=>{
      if(!active)return

      const [profileResult,dynResult,eventResult]=results

      setProfile(
        profileResult.status==='fulfilled'
          ? profileResult.value
          : null
      )

      setDyn(
        dynResult.status==='fulfilled'
          ? dynResult.value
          : null
      )

      if(eventResult.status==='fulfilled'){
        const payload=eventResult.value||{}
        const rows=arr(payload,['events','items','value'])
        setSelectedUserEvents(rows)
        setSelectedUserEventTotal(
          num(payload.total_count,rows.length)
        )
      }else{
        setUserEventError(
          eventResult.reason?.message||
          '사용자 이벤트 조회에 실패했습니다.'
        )
      }
    })

    return()=>{active=false}
  },[selected])'''

if old_effect in app:
    app = app.replace(old_effect, new_effect, 1)
elif "api.userEvents(selected)" not in app:
    raise RuntimeError("UserAnalysisPage selected effect 교체에 실패했습니다.")

old_calc = "  const userEvents=events.filter(e=>String(e.user)===String(selected));const userMax=Math.max(0,...userEvents.map(e=>num(e.risk_score))),userAvg=userEvents.length?userEvents.reduce((s,e)=>s+num(e.risk_score),0)/userEvents.length:0"
new_calc = '''  const userEvents=selectedUserEvents
  const userMax=Math.max(
    0,
    ...userEvents.map(e=>num(e.risk_score))
  )
  const userAvg=userEvents.length
    ? userEvents.reduce((s,e)=>s+num(e.risk_score),0)/userEvents.length
    : 0'''

if old_calc in app:
    app = app.replace(old_calc, new_calc, 1)
elif "const userEvents=selectedUserEvents" not in app:
    raise RuntimeError("UserAnalysisPage userEvents 계산 교체에 실패했습니다.")

app = app.replace(
    "<ProfileView profile={profile} eventCount={userEvents.length}/>",
    "<ProfileView profile={profile} eventCount={selectedUserEventTotal}/>",
    1,
)
app = app.replace(
    '<Kpi title="전체 이벤트" value={userEvents.length} hint="수집된 사용자 활동"/>',
    '<Kpi title="전체 이벤트" value={selectedUserEventTotal.toLocaleString()} hint="선택 사용자의 전체 DB 이벤트"/>',
    1,
)

if "userEventError&&<Notice" not in app:
    app = app.replace(
        '{selected&&<><div className="baseline-summary">',
        '{selected&&<>{userEventError&&<Notice type="error">{userEventError}</Notice>}<div className="baseline-summary">',
        1,
    )

MAIN.write_text(main, encoding="utf-8")
BASELINE.write_text(baseline, encoding="utf-8")
API.write_text(api, encoding="utf-8")
APP.write_text(app, encoding="utf-8")

print()
print("=" * 76)
print("SENTINEL 통합 복구 패치 적용 완료")
print("=" * 76)
print("해결:")
print("  1) 사용자 0명 표시")
print("  2) 전체 이벤트 30,000건 KPI")
print("  3) 전체 Anomaly / High Risk KPI")
print("  4) 이벤트 모니터링 사용자 15명")
print("  5) 사용자 행동 분석 현재 이벤트 0")
print("  6) Adaptive Baseline LEARNING 0건")
print("  7) 전시용 90일 과거 이력 학습 허용")
print("  8) siem_demo 실제 등록시점 보호 유지")
print()
print("검증:")
print("  python -m py_compile server/main.py server/baseline_engine.py")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
print()
print("성공 후:")
print("  cd ..")
print("  git add server/main.py server/baseline_engine.py sentinel-react-frontend/src/api.js sentinel-react-frontend/src/App.jsx")
print('  git commit -m "Fix exhibition dashboard data integration"')
print("  git push")
