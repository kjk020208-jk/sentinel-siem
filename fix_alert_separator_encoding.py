from pathlib import Path
import sys

ROOT = Path.cwd()
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

if not APP.exists():
    print("[ERROR] App.jsx not found")
    sys.exit(1)

app = APP.read_text(encoding="utf-8")

count = app.count("쨌")
if count == 0:
    print("[OK] broken separator not found")
else:
    app = app.replace("쨌", "{'\\u00B7'}")
    APP.write_text(app, encoding="utf-8")
    print(f"[PATCH] replaced broken separators: {count}")
    print("[VERIFY OK] App.jsx updated")
