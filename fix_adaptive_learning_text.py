from pathlib import Path
import shutil
import py_compile

app = Path("dashboard/app_beforealert.py")

if not app.exists():
    raise FileNotFoundError("dashboard/app.py를 찾지 못했습니다.")

text = app.read_text(encoding="utf-8")

old = '''                    if not adaptive_applied:
                        st.markdown("**Adaptive 정상 패턴 보정**")
                        st.markdown(
                            f"- 현재 보정 미적용 · 신뢰도 "
                            f"{adaptive_confidence}"
                        )
'''

new = '''                    if not adaptive_applied:
                        st.markdown("**Adaptive 정상 패턴 보정**")
                        st.markdown(
                            f"- 개인 기준선 엔진 학습 상태: "
                            f"{adaptive_confidence}"
                        )
                        st.markdown(
                            "- 현재 이벤트에는 Adaptive 위험도 감점이 적용되지 않았습니다."
                        )
                        st.caption(
                            "※ LEARNING은 개인 기준선 엔진의 데이터 축적 상태를 의미합니다. "
                            "행동 변화 검증의 OBSERVING / ACCEPTED / REJECTED와는 별도 상태입니다. "
                            "REJECTED된 신규 행동은 정상 기준선 학습 대상에서 제외됩니다."
                        )
'''

if old not in text:
    raise RuntimeError(
        "교체할 Adaptive 문구를 찾지 못했습니다."
    )

backup = Path(
    "dashboard/app.before_adaptive_text_fix.py"
)

shutil.copy2(
    app,
    backup
)

text = text.replace(
    old,
    new,
    1
)

app.write_text(
    text,
    encoding="utf-8"
)

py_compile.compile(
    str(app),
    doraise=True
)

print("[완료] Adaptive LEARNING 문구 수정")
print("[백업] dashboard/app.before_adaptive_text_fix.py")
print("[검사] dashboard/app_beforealert.py 문법 정상")
