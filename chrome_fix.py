from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
ENGINE = ROOT / "server" / "change_verification_engine.py"

if not ENGINE.exists():
    raise FileNotFoundError(f"파일이 없습니다: {ENGINE}")

backup = ENGINE.with_name("change_verification_engine.before_chrome_fix.py")
if not backup.exists():
    shutil.copy2(ENGINE, backup)

text = ENGINE.read_text(encoding="utf-8")

start = text.find("STRONG_RISK_KEYWORDS = (")
if start == -1:
    raise RuntimeError("STRONG_RISK_KEYWORDS를 찾지 못했습니다.")

end = text.find("\n)\n", start)
if end == -1:
    raise RuntimeError("STRONG_RISK_KEYWORDS 끝을 찾지 못했습니다.")
end += 3

new_block = """STRONG_RISK_KEYWORDS = (
    "대외비",
    "민감",
    "USB",
    "반복 로그인 실패",
    "로그인 실패",
    "공격 시퀀스",
    "Sequence",
    "의심 명령",
    "외부 다운로드",
    "대량 파일",
)
"""

text = text[:start] + new_block + text[end:]

compile(text, str(ENGINE), "exec")
ENGINE.write_text(text, encoding="utf-8")

print("=" * 72)
print("[완료] Chrome 과민 REJECTED 수정")
print("=" * 72)
print("[제거] 강한 위험 키워드: '외부 전송', '외부전송'")
print("[유지] Chrome 실행 자체 Rule Score는 기존 로직 그대로")
print("[유지] 위험도 60 이상 / HIGH / CRITICAL은 여전히 강한 위험")
print("[유지] 의심 명령, 외부 다운로드, 대량 파일, 민감정보, USB 등은 강한 위험")
print("[검사] change_verification_engine.py 문법 정상")
