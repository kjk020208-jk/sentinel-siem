from pathlib import Path
import re
import shutil
import sys

ROOT = Path.cwd()
MAIN = ROOT / "server" / "main.py"
BASELINE = ROOT / "server" / "baseline_engine.py"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

for p in (MAIN, BASELINE, APP):
    if not p.exists():
        print("[ERROR] 파일 없음:", p)
        print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
        sys.exit(1)

for p in (MAIN, BASELINE, APP):
    shutil.copy2(p, p.with_name(p.name + ".before_behavior_fix"))

main = MAIN.read_text(encoding="utf-8")
baseline = BASELINE.read_text(encoding="utf-8")
app = APP.read_text(encoding="utf-8")

# ------------------------------------------------------------
# main.py: datetime import
# ------------------------------------------------------------
if "from datetime import datetime, timedelta" not in main:
    main = main.replace(
        "from datetime import datetime",
        "from datetime import datetime, timedelta",
        1,
    )

# ------------------------------------------------------------
# main.py: replace /users endpoint with lightweight version
# ------------------------------------------------------------
users_start = main.find('@app.get("/users")')
users_end = main.find('@app.get("/users/{username}")')

if users_start == -1 or users_end == -1 or users_end <= users_start:
    raise RuntimeError("/users endpoint 범위를 찾지 못했습니다.")

new_users = r'''@app.get("/users")
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

        total_event_count = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user == monitored_user.username
            )
            .count()
        )

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
            "total_event_count": int(total_event_count),
        })

    return results


'''

main = main[:users_start] + new_users + main[users_end:]

# ------------------------------------------------------------
# main.py: replace behavior-profile endpoint
# ------------------------------------------------------------
profile_start = main.find('@app.get("/users/{user}/behavior-profile")')
if profile_start == -1:
    raise RuntimeError("behavior-profile endpoint 시작을 찾지 못했습니다.")

profile_next = main.find("\n@app.", profile_start + 10)
if profile_next == -1:
    raise RuntimeError("behavior-profile endpoint 끝을 찾지 못했습니다.")

new_profile = r'''@app.get("/users/{user}/behavior-profile")
def get_behavior_profile(
    user: str,
    db: Session = Depends(get_db)
):
    profile = get_user_behavior_profile(
        db=db,
        user=user
    )

    event_query = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user == user)
    )

    total_event_count = int(
        event_query.count()
    )

    recent_events = (
        event_query
        .order_by(SecurityEvent.id.desc())
        .limit(1000)
        .all()
    )

    profile["_dashboard_total_event_count"] = total_event_count
    profile["_dashboard_recent_events"] = recent_events

    return profile


'''

main = main[:profile_start] + new_profile + main[profile_next+1:]

# ------------------------------------------------------------
# baseline_engine.py: exhibition history bypass registration guard
# ------------------------------------------------------------
if "exhibition_history_exists" not in baseline:
    old_guard = '''    if (
        monitored_user is not None
        and monitored_user.created_at is not None
        and monitored_user.created_at > learning_since
    ):
        learning_since = monitored_user.created_at
'''

    new_guard = '''    exhibition_history_exists = (
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

    if old_guard not in baseline:
        raise RuntimeError("baseline 등록시점 보호 로직을 찾지 못했습니다.")

    baseline = baseline.replace(old_guard, new_guard, 1)

# ------------------------------------------------------------
# App.jsx: use behavior-profile embedded events
# ------------------------------------------------------------

old_effect = "  useEffect(()=>{if(!selected)return;api.behaviorProfile(selected).then(setProfile).catch(()=>setProfile(null));api.dynamicRisk(selected).then(setDyn).catch(()=>setDyn(null))},[selected])"

new_effect = '''  useEffect(()=>{
    if(!selected)return
    let active=true

    setProfile(null)
    setDyn(null)

    Promise.allSettled([
      api.behaviorProfile(selected),
      api.dynamicRisk(selected),
    ]).then(results=>{
      if(!active)return

      const [profileResult,dynResult]=results

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
    })

    return()=>{active=false}
  },[selected])'''

if old_effect in app:
    app = app.replace(old_effect, new_effect, 1)

old_calc = "  const userEvents=events.filter(e=>String(e.user)===String(selected));const userMax=Math.max(0,...userEvents.map(e=>num(e.risk_score))),userAvg=userEvents.length?userEvents.reduce((s,e)=>s+num(e.risk_score),0)/userEvents.length:0"

new_calc = '''  const userEvents=arr(
    profile?._dashboard_recent_events,
    ['events','items','value']
  )

  const selectedUserEventTotal=num(
    profile?._dashboard_total_event_count,
    userEvents.length
  )

  const userMax=Math.max(
    0,
    ...userEvents.map(e=>num(e.risk_score))
  )

  const userAvg=userEvents.length
    ? userEvents.reduce(
        (s,e)=>s+num(e.risk_score),
        0
      )/userEvents.length
    : 0'''

if old_calc in app:
    app = app.replace(old_calc, new_calc, 1)
elif "profile?._dashboard_recent_events" not in app:
    raise RuntimeError("UserAnalysisPage 이벤트 계산 구문을 찾지 못했습니다.")

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

MAIN.write_text(main, encoding="utf-8")
BASELINE.write_text(baseline, encoding="utf-8")
APP.write_text(app, encoding="utf-8")

print("")
print("=" * 72)
print("SENTINEL 사용자 행동 분석 통합 수정 완료")
print("=" * 72)
print("수정:")
print("- /users 경량화")
print("- 사용자 15명 표시 복구")
print("- 전시용 과거 이벤트 Baseline 학습 허용")
print("- 선택 사용자 전체 이벤트 수 DB 기준 표시")
print("- 선택 사용자 최근 1000건 직접 표시")
print("- api.js 변경 없음")
print("- siem_demo 등록시점 보호 유지")
print("")
print("다음:")
print("python -m py_compile server/main.py server/baseline_engine.py")
print("cd sentinel-react-frontend")
print("npm.cmd run build")
