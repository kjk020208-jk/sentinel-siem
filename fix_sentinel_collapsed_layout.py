from pathlib import Path
import sys

ROOT = Path.cwd()
CSS = ROOT / "sentinel-react-frontend" / "src" / "styles.css"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

if not CSS.exists() or not APP.exists():
    print("ERROR: siemueba 프로젝트 루트에서 실행하세요.")
    print(r"예: C:\Users\김재경\PycharmProjects\siemueba")
    sys.exit(1)

css = CSS.read_text(encoding="utf-8")
app = APP.read_text(encoding="utf-8")

CSS.with_name("styles.before_collapsed_width_fix.css").write_text(css, encoding="utf-8")
APP.with_name("App.before_collapsed_width_fix.jsx").write_text(app, encoding="utf-8")

marker = "/* ===== DEFINITIVE COLLAPSED SIDEBAR WIDTH FIX ===== */"
if marker in css:
    css = css.split(marker)[0].rstrip() + "\n"

patch = r'''
/* ===== DEFINITIVE COLLAPSED SIDEBAR WIDTH FIX ===== */

.sidebar.collapsed{
  width:76px !important;
  min-width:76px !important;
  max-width:76px !important;
}

.sidebar.collapsed + .main{
  margin-left:76px !important;
  width:calc(100vw - 76px) !important;
  min-width:calc(100vw - 76px) !important;
  max-width:calc(100vw - 76px) !important;
  box-sizing:border-box !important;
  display:block !important;
}

.sidebar.collapsed + .main > .content{
  width:100% !important;
  min-width:0 !important;
  max-width:1600px !important;
  box-sizing:border-box !important;
  margin-left:auto !important;
  margin-right:auto !important;
}

.sidebar.collapsed + .main .soc-header,
.sidebar.collapsed + .main .overview-v2,
.sidebar.collapsed + .main .ov2-hero,
.sidebar.collapsed + .main .ov2-metrics,
.sidebar.collapsed + .main .ov2-block,
.sidebar.collapsed + .main .ov2-live-list,
.sidebar.collapsed + .main .ov2-analytics,
.sidebar.collapsed + .main .ov2-table-grid{
  width:100% !important;
  min-width:0 !important;
  max-width:none !important;
  box-sizing:border-box !important;
}

.sidebar.collapsed + .main .ov2-hero{
  display:grid !important;
  grid-template-columns:minmax(0,1.65fr) minmax(280px,.75fr) !important;
  gap:22px !important;
}

.sidebar.collapsed + .main .ov2-metrics{
  display:grid !important;
  grid-template-columns:repeat(4,minmax(0,1fr)) !important;
}

.sidebar.collapsed + .main .ov2-analytics{
  display:grid !important;
  grid-template-columns:minmax(0,1fr) minmax(0,1fr) minmax(300px,.78fr) !important;
  gap:16px !important;
}

.sidebar.collapsed + .main .ov2-table-grid{
  display:grid !important;
  grid-template-columns:1.25fr 1fr !important;
  gap:16px !important;
}

.sidebar.collapsed + .main .soc-title,
.sidebar.collapsed + .main .soc-subtitle,
.sidebar.collapsed + .main .ov2-hero-copy,
.sidebar.collapsed + .main .ov2-hero h2,
.sidebar.collapsed + .main .ov2-hero p,
.sidebar.collapsed + .main .ov2-card-head,
.sidebar.collapsed + .main .ov2-section-head{
  width:auto !important;
  min-width:0 !important;
  max-width:none !important;
  word-break:keep-all !important;
  overflow-wrap:normal !important;
  white-space:normal !important;
}

.app-shell.sidebar-collapsed .main{
  margin-left:76px !important;
  width:calc(100vw - 76px) !important;
  min-width:calc(100vw - 76px) !important;
  max-width:calc(100vw - 76px) !important;
}

@media(max-width:1200px){
  .sidebar.collapsed{
    width:72px !important;
    min-width:72px !important;
    max-width:72px !important;
  }

  .sidebar.collapsed + .main,
  .app-shell.sidebar-collapsed .main{
    margin-left:72px !important;
    width:calc(100vw - 72px) !important;
    min-width:calc(100vw - 72px) !important;
    max-width:calc(100vw - 72px) !important;
  }

  .sidebar.collapsed + .main .ov2-hero{
    grid-template-columns:1fr !important;
  }

  .sidebar.collapsed + .main .ov2-analytics{
    grid-template-columns:1fr 1fr !important;
  }

  .sidebar.collapsed + .main .ov2-risk-card{
    grid-column:1 / -1 !important;
  }
}
'''

CSS.write_text(css.rstrip() + "\n\n" + patch.strip() + "\n", encoding="utf-8")

if "hole:.73" in app:
    app = app.replace("hole:.73", "hole:.80", 1)
    APP.write_text(app, encoding="utf-8")
    donut = "도넛 hole .73 -> .80 적용"
elif "hole: .73" in app:
    app = app.replace("hole: .73", "hole: .80", 1)
    APP.write_text(app, encoding="utf-8")
    donut = "도넛 hole .73 -> .80 적용"
else:
    donut = "도넛 두께는 기존 설정 유지"

print("")
print("============================================")
print(" 접힌 사이드바 본문 폭 수정 완료")
print("============================================")
print("- sidebar.collapsed + main 직접 지정")
print("- 오른쪽 본문 = viewport 남은 전체 폭")
print("- Hero / KPI / Analytics / Table 레이아웃 복원")
print("- 한글 세로 찌그러짐 방지")
print("-", donut)
print("")
print("다음 명령:")
print("cd sentinel-react-frontend")
print("npm.cmd run build")
