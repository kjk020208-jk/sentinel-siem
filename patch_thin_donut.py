from pathlib import Path
import sys

app = Path("sentinel-react-frontend/src/App.jsx")

if not app.exists():
    print("ERROR: siemueba 프로젝트 루트에서 실행하세요.")
    sys.exit(1)

text = app.read_text(encoding="utf-8")

if "hole:.73" in text:
    text = text.replace("hole:.73", "hole:.80", 1)
elif "hole: .73" in text:
    text = text.replace("hole: .73", "hole: .80", 1)
elif "hole:.80" in text or "hole: .80" in text:
    print("도넛 두께는 이미 수정되어 있습니다.")
else:
    print("ERROR: Plotly donut hole 값을 찾지 못했습니다.")
    sys.exit(1)

backup = app.with_name("App.before_thin_donut.jsx")
backup.write_text(app.read_text(encoding="utf-8"), encoding="utf-8")
app.write_text(text, encoding="utf-8")

print("도넛 링 두께 수정 완료: hole .73 -> .80")
print("백업:", backup)
