from pathlib import Path
import sys

ROOT = Path.cwd()
CSS = ROOT / "sentinel-react-frontend" / "src" / "styles.css"

if not CSS.exists():
    print("ERROR: siemueba 프로젝트 루트에서 실행하세요.")
    print(r"예: C:\Users\김재경\PycharmProjects\siemueba")
    sys.exit(1)

css = CSS.read_text(encoding="utf-8")

backup = CSS.with_name("styles.before_login_minimal.css")
backup.write_text(css, encoding="utf-8")

marker = "/* ===== SENTINEL MINIMAL LOGIN FINAL ===== */"
if marker in css:
    css = css.split(marker)[0].rstrip() + "\n"

patch = r'''
/* ===== SENTINEL MINIMAL LOGIN FINAL ===== */

/* Keep only SENTINEL branding above the form. */
.sentinel-login-content h1,
.sentinel-login-description{
  display:none !important;
}

/* Remove excessive title-area spacing created by the old hero copy. */
.sentinel-login-content{
  width:min(390px,calc(100vw - 40px)) !important;
  padding-top:0 !important;
}

.sentinel-login-brand{
  margin:0 0 42px !important;
  padding:0 0 24px !important;

  color:#f5f5f7 !important;
  font-size:19px !important;
  line-height:1 !important;
  font-weight:760 !important;
  letter-spacing:.24em !important;

  border-bottom:1px solid rgba(255,255,255,.055) !important;
}

/* Form sits directly beneath SENTINEL. */
.sentinel-login-form{
  margin-top:0 !important;
}

/* Slightly tighter, cleaner login composition. */
.sentinel-login-form label{
  margin:0 !important;
}

.sentinel-login-form label + label{
  margin-top:14px !important;
}

.sentinel-login-button{
  margin-top:18px !important;
}

/* Keep security notice subtle. */
.sentinel-login-security{
  margin-top:25px !important;
}

/* Footer becomes less visually distracting. */
.sentinel-login-footer{
  opacity:.58 !important;
}
'''

CSS.write_text(css.rstrip() + "\n\n" + patch.strip() + "\n", encoding="utf-8")

print("")
print("======================================")
print(" SENTINEL 로그인 화면 단순화 완료")
print("======================================")
print("- Security Operations Center 숨김")
print("- 설명 문구 숨김")
print("- SENTINEL 바로 아래 로그인 폼 배치")
print("- 기존 로그인 기능 변경 없음")
print("")
print("다음:")
print("cd sentinel-react-frontend")
print("npm.cmd run build")
