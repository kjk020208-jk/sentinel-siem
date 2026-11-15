from pathlib import Path
import re
import sys
import shutil

ROOT = Path.cwd()
MAIN = ROOT / "server" / "main.py"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
API = ROOT / "sentinel-react-frontend" / "src" / "api.js"

missing = [str(p) for p in (MAIN, APP, API) if not p.exists()]
if missing:
    print("[ERROR] 필요한 파일을 찾지 못했습니다.")
    for p in missing:
        print(" -", p)
    print(r"siemueba 프로젝트 루트(C:\Users\김재경\PycharmProjects\siemueba)에서 실행하세요.")
    sys.exit(1)

for p in (MAIN, APP, API):
    shutil.copy2(p, p.with_name(p.name + ".before_full_summary_fix"))

main = MAIN.read_text(encoding="utf-8")
app = APP.read_text(encoding="utf-8")
api = API.read_text(encoding="utf-8")

# 1) Backend summary endpoint
if '@app.get("/events/summary")' not in main:
    anchor = '@app.get("/events")\ndef get_events('
    if anchor not in main:
        print('[ERROR] server/main.py에서 @app.get("/events")를 찾지 못했습니다.')
        sys.exit(1)

    endpoint = """
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

    query = db.query(SecurityEvent).filter(
        SecurityEvent.user.in_(active_users)
    )

    total_events = query.count()

    anomalies = query.filter(
        SecurityEvent.anomaly_score >= 50
    ).count()

    high_risk = query.filter(
        SecurityEvent.risk_level.in_(["HIGH", "CRITICAL"])
    ).count()

    critical = query.filter(
        SecurityEvent.risk_level == "CRITICAL"
    ).count()

    return {
        "total_events": int(total_events),
        "anomalies": int(anomalies),
        "high_risk": int(high_risk),
        "critical": int(critical),
        "active_users": int(len(active_users)),
    }


"""
    main = main.replace(anchor, endpoint + anchor, 1)

# 2) api.js: clone events call
if "eventSummary" not in api:
    lines = api.splitlines()
    inserted = False

    for i, line in enumerate(lines):
        if re.search(r"\bevents\s*:", line) and re.search(r"[\"']/events(?:\?[^\"']*)?[\"']", line):
            cloned = re.sub(r"\bevents\s*:", "eventSummary:", line, count=1)
            cloned = re.sub(
                r"([\"'])/events(?:\?[^\"']*)?\1",
                lambda m: f"{m.group(1)}/events/summary{m.group(1)}",
                cloned,
                count=1,
            )
            lines.insert(i + 1, cloned)
            api = "\n".join(lines) + ("\n" if api.endswith("\n") else "")
            inserted = True
            break

    if not inserted:
        print("[ERROR] api.js에서 기존 events API 정의를 찾지 못했습니다.")
        sys.exit(1)

# 3) App summary polling
if "eventSummaryRaw" not in app:
    pattern = re.compile(
        r"(?P<indent>[ \t]*)const \[eventsRaw,eventsErr,,eventsLatency\]=usePolling"
        r"\(api\.events,autoRefresh\?3000:86400000,refreshKey\)"
    )
    m = pattern.search(app)
    if not m:
        print("[ERROR] App.jsx에서 events polling 구문을 찾지 못했습니다.")
        sys.exit(1)

    original = m.group(0)
    indent = m.group("indent")
    replacement = (
        original
        + "\n"
        + indent
        + "const [eventSummaryRaw]=usePolling(api.eventSummary,autoRefresh?3000:86400000,refreshKey)"
    )
    app = app[:m.start()] + replacement + app[m.end():]

# 4) Props
app = app.replace(
    "<OverviewV2 events={events} users={users} latestIncident={latestIncident}",
    "<OverviewV2 events={events} users={users} summary={eventSummaryRaw} latestIncident={latestIncident}",
)
app = app.replace(
    "<Overview events={events} users={users} latestIncident={latestIncident}",
    "<Overview events={events} users={users} summary={eventSummaryRaw} latestIncident={latestIncident}",
)
app = app.replace(
    "<EventsPage events={events}/>",
    "<EventsPage events={events} monitoredUsers={users} summary={eventSummaryRaw}/>",
)

# 5) OverviewV2 signature
app = app.replace(
    "function OverviewV2({events,users,latestIncident,setPage,error,latency})",
    "function OverviewV2({events,users,summary,latestIncident,setPage,error,latency})",
)
app = app.replace(
    "function Overview({events,users,latestIncident,setPage,error,latency})",
    "function Overview({events,users,summary,latestIncident,setPage,error,latency})",
)

# Overview headline KPI
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

# 6) EventsPage signature and user list
app = app.replace(
    "function EventsPage({events}){",
    "function EventsPage({events,monitoredUsers=[],summary}){",
    1,
)

old_lists = "  const levels=['전체',...new Set(events.map(e=>e.risk_level).filter(Boolean))],users=['전체',...new Set(events.map(e=>e.user).filter(Boolean))],types=['전체',...new Set(events.map(e=>koEvent(e.event_type)).filter(Boolean))]"

new_lists = """  const levels=['전체',...new Set(events.map(e=>e.risk_level).filter(Boolean))]
  const monitoredUserNames=monitoredUsers
    .filter(u=>u.monitoring_enabled===true||u.enabled===true||u.is_enabled===true)
    .map(u=>String(u.username||u.user||''))
    .filter(Boolean)
  const users=['전체',...new Set(monitoredUserNames.length?monitoredUserNames:events.map(e=>e.user).filter(Boolean))]
  const types=['전체',...new Set(events.map(e=>koEvent(e.event_type)).filter(Boolean))]"""

if old_lists in app:
    app = app.replace(old_lists, new_lists, 1)
elif "const monitoredUserNames=" not in app:
    print("[ERROR] EventsPage 사용자 목록 구문을 찾지 못했습니다.")
    sys.exit(1)

# Insert KPI helpers after filtered line
if "const hasEventFilter=" not in app:
    filtered_pattern = re.compile(r"(?P<indent>[ \t]*)const filtered=events\.filter\([^\n]+\)")
    m = filtered_pattern.search(app)
    if not m:
        print("[ERROR] EventsPage filtered 구문을 찾지 못했습니다.")
        sys.exit(1)

    helpers = """  const hasEventFilter=
    level!=='전체'||
    user!=='전체'||
    type!=='전체'||
    Boolean(search.trim())

  const visibleEventCount=hasEventFilter
    ? filtered.length
    : num(summary?.total_events,filtered.length)

  const visibleCritical=hasEventFilter
    ? filtered.filter(e=>String(e.risk_level).toUpperCase()==='CRITICAL').length
    : num(summary?.critical,filtered.filter(e=>String(e.risk_level).toUpperCase()==='CRITICAL').length)

  const visibleHigh=hasEventFilter
    ? filtered.filter(e=>String(e.risk_level).toUpperCase()==='HIGH').length
    : Math.max(0,num(summary?.high_risk,0)-num(summary?.critical,0))

  const visibleUsers=hasEventFilter
    ? new Set(filtered.map(e=>e.user).filter(Boolean)).size
    : num(
        summary?.active_users,
        monitoredUserNames.length||
        new Set(filtered.map(e=>e.user).filter(Boolean)).size
      )"""

    replacement = m.group(0) + "\n" + helpers
    app = app[:m.start()] + replacement + app[m.end():]

old_kpis = '<SectionHeader>모니터링 현황</SectionHeader><div className="kpis compact"><Kpi title="조회 이벤트" value={filtered.length} hint="현재 필터 조건"/><Kpi title="CRITICAL" value={filtered.filter(e=>e.risk_level===\'CRITICAL\').length} hint="긴급 위험 이벤트" danger/><Kpi title="HIGH" value={filtered.filter(e=>e.risk_level===\'HIGH\').length} hint="고위험 이벤트" warning/><Kpi title="사용자" value={new Set(filtered.map(e=>e.user).filter(Boolean)).size} hint="조회된 사용자"/></div>'

new_kpis = '<SectionHeader>모니터링 현황</SectionHeader><div className="kpis compact"><Kpi title="조회 이벤트" value={visibleEventCount.toLocaleString()} hint={hasEventFilter?\'현재 로딩 구간의 필터 결과\':\'전체 모니터링 이벤트\'}/><Kpi title="CRITICAL" value={visibleCritical.toLocaleString()} hint="긴급 위험 이벤트" danger/><Kpi title="HIGH" value={visibleHigh.toLocaleString()} hint="고위험 이벤트" warning/><Kpi title="사용자" value={visibleUsers.toLocaleString()} hint={hasEventFilter?\'현재 필터 결과 사용자\':\'활성 모니터링 사용자\'}/></div>'

if old_kpis in app:
    app = app.replace(old_kpis, new_kpis, 1)
elif "value={visibleEventCount.toLocaleString()}" not in app:
    print("[ERROR] EventsPage KPI 구문을 찾지 못했습니다.")
    sys.exit(1)

MAIN.write_text(main, encoding="utf-8")
API.write_text(api, encoding="utf-8")
APP.write_text(app, encoding="utf-8")

print("")
print("=" * 72)
print("SENTINEL 전체 통계 / 사용자 15명 표시 패치 완료")
print("=" * 72)
print("Overview:")
print("  Events      -> 전체 DB 이벤트")
print("  Anomalies   -> 전체 DB 이상행동")
print("  High Risk   -> 전체 DB HIGH + CRITICAL")
print("  Users       -> 활성 모니터링 사용자")
print("")
print("이벤트 모니터링:")
print("  조회 이벤트 -> 기본 상태에서 전체 DB 건수")
print("  사용자       -> 기본 상태에서 활성 사용자 전체")
print("  사용자 필터  -> 등록된 활성 사용자 전체")
print("  이벤트 표    -> 최근 500건 유지")
print("")
print("다음:")
print("  python -m py_compile server/main.py")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
print("")
print("성공 후:")
print("  cd ..")
print("  git add server/main.py sentinel-react-frontend/src/api.js sentinel-react-frontend/src/App.jsx")
print('  git commit -m "Add full event summary metrics"')
print("  git push")
