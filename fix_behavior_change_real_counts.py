from pathlib import Path
import re
import shutil
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

if not APP.exists():
    print("[ERROR] App.jsx를 찾지 못했습니다.")
    print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
    sys.exit(1)

shutil.copy2(
    APP,
    APP.with_name("App.before_behavior_summary_fix.jsx")
)

app = APP.read_text(encoding="utf-8")

# 1) App-level polling
if "behaviorChangesRaw" not in app:
    pattern = re.compile(
        r'(?P<line>[ \t]*const \[usersRaw\]=usePolling'
        r'\(api\.users,[^\n]+\))'
    )
    m = pattern.search(app)
    if not m:
        raise RuntimeError("usersRaw polling 구문을 찾지 못했습니다.")

    replacement = (
        m.group("line")
        + "\n"
        + "  const [behaviorChangesRaw]=usePolling("
          "api.behaviorChanges,"
          "autoRefresh?10000:86400000,"
          "refreshKey"
          ")"
    )
    app = app[:m.start()] + replacement + app[m.end():]

# 2) Pass prop to OverviewV2
if "behaviorChanges={behaviorChangesRaw}" not in app:
    app = app.replace(
        "<OverviewV2 events={events} users={users} summary={eventSummaryRaw} latestIncident={latestIncident}",
        "<OverviewV2 events={events} users={users} summary={eventSummaryRaw} behaviorChanges={behaviorChangesRaw} latestIncident={latestIncident}",
        1,
    )
    app = app.replace(
        "<OverviewV2 events={events} users={users} latestIncident={latestIncident}",
        "<OverviewV2 events={events} users={users} behaviorChanges={behaviorChangesRaw} latestIncident={latestIncident}",
        1,
    )

# 3) Signature
app = app.replace(
    "function OverviewV2({events,users,summary,latestIncident,setPage,error,latency})",
    "function OverviewV2({events,users,summary,behaviorChanges,latestIncident,setPage,error,latency})",
    1,
)
app = app.replace(
    "function OverviewV2({events,users,latestIncident,setPage,error,latency})",
    "function OverviewV2({events,users,behaviorChanges,latestIncident,setPage,error,latency})",
    1,
)

# 4) Replace V2 behavior summary parser
v2_start = app.find("function OverviewV2(")
alerts_pos = app.find("  const alerts=events.filter(", v2_start)
bc_start = app.find("  const bc={", v2_start, alerts_pos)

if v2_start == -1 or alerts_pos == -1:
    raise RuntimeError("OverviewV2 범위를 찾지 못했습니다.")

new_block = """  const behaviorRows=arr(
    behaviorChanges,
    ['items','value','behavior_changes']
  )

  const bc=behaviorRows.reduce(
    (acc,row)=>{
      const status=String(
        row?.status||''
      ).toUpperCase()

      if(status==='OBSERVING'){
        acc.OBSERVING++
      }else if(status==='ACCEPTED'){
        acc.ACCEPTED++
      }else if(status==='REJECTED'){
        acc.REJECTED++
      }

      return acc
    },
    {
      OBSERVING:0,
      ACCEPTED:0,
      REJECTED:0
    }
  )

"""

if bc_start != -1:
    app = app[:bc_start] + new_block + app[alerts_pos:]
elif "const behaviorRows=arr(" not in app[v2_start:alerts_pos]:
    raise RuntimeError("OverviewV2 행동 변화 집계 구문을 찾지 못했습니다.")

# 5) Label
app = app.replace(
    "<span>BASELINE</span>\n              <h3>행동 변화 검증</h3>",
    "<span>BEHAVIOR CHANGE</span>\n              <h3>행동 변화 검증</h3>",
    1,
)

APP.write_text(app, encoding="utf-8")

print("")
print("=" * 72)
print("Behavior Change 실제 DB 집계 수정 완료")
print("=" * 72)
print("- api.behaviorChanges() 사용")
print("- OBSERVING / ACCEPTED / REJECTED 실제 status 집계")
print("- 10초 자동 갱신")
print("- 최근 500개 이벤트 reasons 파싱 제거")
print("")
print("다음:")
print("cd sentinel-react-frontend")
print("npm.cmd run build")
