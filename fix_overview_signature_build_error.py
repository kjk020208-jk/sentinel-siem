from pathlib import Path
import re
import shutil
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

if not APP.exists():
    print("[ERROR] App.jsx not found")
    sys.exit(1)

backup = APP.with_name(APP.name + ".before_overview_signature_fix")
if not backup.exists():
    shutil.copy2(APP, backup)
    print("[BACKUP]", backup.relative_to(ROOT))

app = APP.read_text(encoding="utf-8")
original = app

# Broken shape produced by previous patch:
# function Overview({
#   const[overviewAckEventId,setOverviewAckEventId]=useState('')events,users,...
# }){
broken = re.compile(
    r"function\s+(OverviewV2|Overview)\s*\(\{\s*"
    r"const\[overviewAckEventId,setOverviewAckEventId\]=useState\(''\)"
    r"\s*([^}]*)\}\)\s*\{",
    re.S
)

m = broken.search(app)

if m:
    name = m.group(1)
    params = m.group(2).strip()
    replacement = (
        f"function {name}({{{params}}}){{\n"
        "  const[overviewAckEventId,setOverviewAckEventId]=useState('')"
    )
    app = app[:m.start()] + replacement + app[m.end():]
    print(f"[PATCH] repaired {name} function signature")
else:
    # Alternate exact corruption visible in build log:
    alt = re.compile(
        r"function\s+(OverviewV2|Overview)\s*\(\{\s*"
        r"const\[overviewAckEventId,setOverviewAckEventId\]=useState\(''\)"
        r"([^)]*)\}\)\s*\{",
        re.S
    )
    m = alt.search(app)
    if not m:
        raise RuntimeError("Broken Overview function signature not found")
    name = m.group(1)
    params = m.group(2).strip()
    replacement = (
        f"function {name}({{{params}}}){{\n"
        "  const[overviewAckEventId,setOverviewAckEventId]=useState('')"
    )
    app = app[:m.start()] + replacement + app[m.end():]
    print(f"[PATCH] repaired {name} function signature (fallback)")

# Verification
if "const[overviewAckEventId,setOverviewAckEventId]=useState('')events" in app:
    raise RuntimeError("VERIFY FAILED: corrupted token still exists")

if not re.search(
    r"function\s+(OverviewV2|Overview)\s*\(\{[^}]*events[^}]*\}\)\s*\{\s*"
    r"const\[overviewAckEventId,setOverviewAckEventId\]=useState\(''\)",
    app,
    re.S
):
    raise RuntimeError("VERIFY FAILED: repaired function shape not found")

if "overview-live-critical-alert" not in app:
    raise RuntimeError("VERIFY FAILED: alert UI missing")

if "latestRiskEventForAlert" not in app:
    raise RuntimeError("VERIFY FAILED: alert logic missing")

APP.write_text(app, encoding="utf-8")

print("[VERIFY OK] Overview function syntax repaired")
print("[VERIFY OK] alert logic preserved")
print("[WRITE]", APP.relative_to(ROOT))
