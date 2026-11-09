from pathlib import Path
import shutil
import py_compile

app = Path("dashboard/app_beforealert.py")

if not app.exists():
    raise FileNotFoundError("dashboard/app.py를 찾지 못했습니다.")

text = app.read_text(encoding="utf-8")

if 'elif page == "CERT 100K 검증":' in text:
    print("[SKIP] CERT 100K 검증 페이지가 이미 있습니다.")
    raise SystemExit


# =========================================================
# 1. 사이드바 메뉴 추가
# =========================================================

sidebar_anchor = '''if st.sidebar.button(
    "사용자 행동 분석",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "사용자 행동 분석"
        else "secondary"
    )
):
    st.session_state["page"] = "사용자 행동 분석"
    st.rerun()
'''

sidebar_new = sidebar_anchor + '''

if st.sidebar.button(
    "CERT 100K 검증",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "CERT 100K 검증"
        else "secondary"
    )
):
    st.session_state["page"] = "CERT 100K 검증"
    st.rerun()
'''

if sidebar_anchor not in text:
    raise RuntimeError("사이드바 메뉴 위치를 찾지 못했습니다.")

text = text.replace(
    sidebar_anchor,
    sidebar_new,
    1
)


# =========================================================
# 2. page_info 추가
# =========================================================

page_anchor = '''    "사용자 행동 분석": (
        "사용자 행동 분석",
        "사용자별 행동 패턴 · 위험도 · 활동 이력 분석"
    )
'''

page_new = '''    "사용자 행동 분석": (
        "사용자 행동 분석",
        "사용자별 행동 패턴 · 위험도 · 활동 이력 분석"
    ),
    "CERT 100K 검증": (
        "CERT 100K 성능 검증",
        "CERT Insider Threat Dataset r4.2 · 100,000건 기반 탐지 성능 평가"
    )
'''

if page_anchor not in text:
    raise RuntimeError("page_info 위치를 찾지 못했습니다.")

text = text.replace(
    page_anchor,
    page_new,
    1
)


# =========================================================
# 3. CERT 검증 페이지 추가
# =========================================================

footer_marker = '''# =========================================================
# Footer
# =========================================================
'''

if footer_marker not in text:
    raise RuntimeError("Footer 위치를 찾지 못했습니다.")

cert_page = r'''
# =========================================================
# PAGE 5
# CERT 100K 검증
# =========================================================

elif page == "CERT 100K 검증":

    section_header("평가 데이터 구성")

    st.caption(
        "CERT Insider Threat Dataset r4.2에서 logon · device · file 이벤트를 "
        "공통 스키마로 변환하여 100,000건의 통제된 평가 샘플을 구성했습니다."
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "평가 이벤트",
            "100,000"
        )

    with c2:
        st.metric(
            "악성 이벤트",
            "2,993"
        )

    with c3:
        st.metric(
            "정상 이벤트",
            "97,007"
        )

    with c4:
        st.metric(
            "탐지 Threshold",
            "24"
        )

    st.info(
        "평가 샘플은 CERT 원본 분포 그대로가 아니라, "
        "선택한 악성 이벤트 2,993건을 모두 포함하고 정상 이벤트를 무작위 샘플링한 "
        "통제된 100K 평가셋입니다."
    )


    section_header("Confusion Matrix")

    confusion_df = pd.DataFrame(
        [
            {
                "실제 / 예측": "실제 악성",
                "위험 탐지": 552,
                "정상 판정": 2441
            },
            {
                "실제 / 예측": "실제 정상",
                "위험 탐지": 5619,
                "정상 판정": 91388
            }
        ]
    )

    st.dataframe(
        confusion_df,
        use_container_width=True,
        hide_index=True
    )

    cm1, cm2, cm3, cm4 = st.columns(4)

    with cm1:
        st.metric(
            "TP",
            "552",
            help="실제 악성 이벤트를 위험으로 탐지"
        )

    with cm2:
        st.metric(
            "FP",
            "5,619",
            help="정상 이벤트를 위험으로 탐지"
        )

    with cm3:
        st.metric(
            "TN",
            "91,388",
            help="정상 이벤트를 정상으로 판정"
        )

    with cm4:
        st.metric(
            "FN",
            "2,441",
            help="악성 이벤트를 정상으로 판정"
        )


    section_header("이벤트 단위 성능")

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric(
            "Precision",
            "8.95%"
        )

    with m2:
        st.metric(
            "Recall",
            "18.44%"
        )

    with m3:
        st.metric(
            "False Positive Rate",
            "5.79%"
        )

    with m4:
        st.metric(
            "F1 Score",
            "12.05%"
        )

    st.warning(
        "이벤트 단위 Recall은 낮습니다. CERT 라벨은 하나의 공격 시나리오 안에서도 "
        "여러 하위 이벤트를 각각 악성으로 표시하지만, SENTINEL은 모든 하위 이벤트를 "
        "독립 경보로 발생시키기보다 의미 있는 위험 흐름과 핵심 이벤트를 선택적으로 탐지하도록 설계했습니다."
    )


    section_header("공격 시나리오 단위 탐지")

    scenario1, scenario2, scenario3 = st.columns(3)

    with scenario1:
        st.metric(
            "전체 공격 시나리오",
            "70"
        )

    with scenario2:
        st.metric(
            "탐지 시나리오",
            "70"
        )

    with scenario3:
        st.metric(
            "Scenario Detection",
            "100%"
        )

    st.success(
        "Threshold 24 기준으로 각 CERT 공격 시나리오에서 "
        "최소 1개 이상의 라벨된 악성 이벤트가 탐지되어 70/70 시나리오를 식별했습니다."
    )

    st.caption(
        "※ 이는 '모든 악성 이벤트를 100% 탐지했다'는 의미가 아닙니다. "
        "각 공격 시나리오에서 최소 1개 이상의 핵심 악성 이벤트를 탐지했다는 의미입니다."
    )


    section_header("Threshold 선택 근거")

    threshold_df = pd.DataFrame(
        [
            {
                "Threshold": 23.0,
                "Recall (%)": 27.00,
                "FPR (%)": 8.64,
                "Scenario Detection (%)": 100.00
            },
            {
                "Threshold": 23.5,
                "Recall (%)": 22.08,
                "FPR (%)": 7.35,
                "Scenario Detection (%)": 100.00
            },
            {
                "Threshold": 24.0,
                "Recall (%)": 18.44,
                "FPR (%)": 5.79,
                "Scenario Detection (%)": 100.00
            },
            {
                "Threshold": 24.5,
                "Recall (%)": None,
                "FPR (%)": 5.42,
                "Scenario Detection (%)": 98.57
            },
            {
                "Threshold": 25.0,
                "Recall (%)": None,
                "FPR (%)": 5.09,
                "Scenario Detection (%)": 97.14
            },
            {
                "Threshold": 26.0,
                "Recall (%)": None,
                "FPR (%)": 3.06,
                "Scenario Detection (%)": 90.00
            },
            {
                "Threshold": 27.0,
                "Recall (%)": None,
                "FPR (%)": 1.89,
                "Scenario Detection (%)": 87.14
            },
            {
                "Threshold": 30.0,
                "Recall (%)": 3.68,
                "FPR (%)": 0.35,
                "Scenario Detection (%)": 52.86
            }
        ]
    )

    st.dataframe(
        threshold_df,
        use_container_width=True,
        hide_index=True
    )

    chart_df = threshold_df[
        [
            "Threshold",
            "FPR (%)",
            "Scenario Detection (%)"
        ]
    ].copy()

    chart_df = chart_df.set_index(
        "Threshold"
    )

    st.line_chart(
        chart_df,
        height=320
    )

    st.markdown(
        "**Threshold 24 선택 이유**"
    )

    st.markdown(
        "- Threshold를 24보다 높이면 오탐률은 더 감소하지만 공격 시나리오 탐지율이 떨어지기 시작합니다."
    )

    st.markdown(
        "- Threshold 24에서는 Scenario Detection 100%를 유지하면서 FPR을 5.79%까지 낮췄습니다."
    )

    st.markdown(
        "- 따라서 현재 SENTINEL은 공격 흐름 보존과 오탐 억제 사이의 균형점으로 24를 사용합니다."
    )


    section_header("검증 결과 해석")

    interpretation_df = pd.DataFrame(
        [
            {
                "평가 관점": "대규모 처리",
                "결과": "100,000건 처리 완료",
                "해석": "교수 피드백의 10만 건 이상 데이터 검증 조건 충족"
            },
            {
                "평가 관점": "이벤트 단위 탐지",
                "결과": "Recall 18.44%",
                "해석": "모든 악성 하위 이벤트를 개별 경보로 탐지하지는 않음"
            },
            {
                "평가 관점": "오탐",
                "결과": "FPR 5.79%",
                "해석": "Threshold 30 대비 탐지 민감도를 높인 만큼 일부 정상 이벤트 오탐 존재"
            },
            {
                "평가 관점": "공격 흐름 탐지",
                "결과": "70/70 · 100%",
                "해석": "모든 평가 공격 시나리오에서 최소 1개 이상의 핵심 악성 이벤트 탐지"
            },
            {
                "평가 관점": "향후 개선",
                "결과": "Precision 8.95%",
                "해석": "행동 기준선과 맥락 검증을 추가 학습하여 오탐을 더 줄일 필요"
            }
        ]
    )

    st.dataframe(
        interpretation_df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "평가 기준 · CERT r4.2 통제 샘플 100,000건 · "
        "Threshold 24 · 이벤트 단위 및 시나리오 단위 평가 병행"
    )



'''

text = text.replace(
    footer_marker,
    cert_page + footer_marker,
    1
)


# =========================================================
# 백업 + 저장
# =========================================================

backup = Path(
    "dashboard/app.before_cert100k_page.py"
)

shutil.copy2(
    app,
    backup
)

app.write_text(
    text,
    encoding="utf-8"
)

py_compile.compile(
    str(app),
    doraise=True
)

print("[완료] CERT 100K 검증 페이지 추가")
print("[백업] dashboard/app.before_cert100k_page.py")
print("[검사] dashboard/app_beforealert.py 문법 정상")
print("[메뉴] CERT 100K 검증")
