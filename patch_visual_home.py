from pathlib import Path
import shutil
import py_compile

app = Path("dashboard/app_beforealert.py")

if not app.exists():
    raise FileNotFoundError("dashboard/app.py를 찾지 못했습니다.")

text = app.read_text(encoding="utf-8")

# ---------------------------------------------------------
# 1. Plotly import 추가
# ---------------------------------------------------------

if "import plotly.graph_objects as go" not in text:
    import_anchor = "import requests\n"

    if import_anchor not in text:
        raise RuntimeError("import 위치를 찾지 못했습니다.")

    text = text.replace(
        import_anchor,
        import_anchor
        + "import plotly.graph_objects as go\n"
        + "import re\n",
        1
    )


# ---------------------------------------------------------
# 2. 보안 현황 페이지 위치 찾기
# ---------------------------------------------------------

page1_start = text.find(
    'if page == "보안 현황":'
)

page2_marker = '''# =========================================================
# PAGE 2
# 이벤트 모니터링
# =========================================================
'''

page2_start = text.find(
    page2_marker,
    page1_start
)

if page1_start == -1:
    raise RuntimeError("보안 현황 페이지를 찾지 못했습니다.")

if page2_start == -1:
    raise RuntimeError("이벤트 모니터링 페이지 시작점을 찾지 못했습니다.")


# ---------------------------------------------------------
# 3. 새로운 첫 화면
# ---------------------------------------------------------

new_page1 = r'''if page == "보안 현황":

    # =====================================================
    # 기본 현황
    # =====================================================

    section_header(
        "보안 현황"
    )

    st.caption(
        "최근 수집된 보안 이벤트를 기준으로 현재 위험 상태와 "
        "우선 확인이 필요한 항목을 요약합니다."
    )

    render_kpis(
        df
    )


    # =====================================================
    # 한눈에 보는 보안 상태
    # =====================================================

    section_header(
        "한눈에 보는 보안 상태"
    )

    visual1, visual2, visual3 = st.columns(
        [1, 1, 1]
    )


    # -----------------------------------------------------
    # 위험 등급 도넛
    # -----------------------------------------------------

    with visual1:

        level_labels = {
            "LOW": "낮음",
            "MEDIUM": "주의",
            "HIGH": "높음",
            "CRITICAL": "심각"
        }

        level_colors = {
            "LOW": "#22c55e",
            "MEDIUM": "#eab308",
            "HIGH": "#f97316",
            "CRITICAL": "#ef4444"
        }

        risk_values = [
            int(risk_counts.get(level, 0))
            for level in risk_order
        ]

        risk_labels = [
            level_labels[level]
            for level in risk_order
        ]

        risk_colors = [
            level_colors[level]
            for level in risk_order
        ]

        risk_fig = go.Figure(
            data=[
                go.Pie(
                    labels=risk_labels,
                    values=risk_values,
                    hole=0.68,
                    marker=dict(
                        colors=risk_colors
                    ),
                    textinfo="percent",
                    hovertemplate=(
                        "%{label}<br>"
                        "%{value}건<br>"
                        "%{percent}"
                        "<extra></extra>"
                    )
                )
            ]
        )

        risk_fig.update_layout(
            title=dict(
                text="위험 등급 분포",
                font=dict(
                    size=15,
                    color="#e5e7eb"
                )
            ),
            annotations=[
                dict(
                    text=f"{len(df):,}<br><span style='font-size:11px'>전체 이벤트</span>",
                    x=0.5,
                    y=0.5,
                    showarrow=False,
                    font=dict(
                        size=22,
                        color="#f8fafc"
                    )
                )
            ],
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(
                color="#94a3b8"
            ),
            legend=dict(
                orientation="h",
                y=-0.08,
                x=0.5,
                xanchor="center"
            ),
            margin=dict(
                l=10,
                r=10,
                t=45,
                b=35
            ),
            height=330
        )

        st.plotly_chart(
            risk_fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )


    # -----------------------------------------------------
    # 이벤트 유형 도넛
    # -----------------------------------------------------

    with visual2:

        if "event_type" in df.columns:

            type_series = (
                df["event_type"]
                .fillna("unknown")
                .astype(str)
                .apply(event_type_korean)
                .value_counts()
            )

            # 상위 6개만 표시하고 나머지는 기타로 묶음
            if len(type_series) > 6:

                top_types = type_series.head(6)

                other_count = int(
                    type_series.iloc[6:].sum()
                )

                type_series = top_types.copy()

                if other_count > 0:
                    type_series.loc["기타"] = other_count

        else:
            type_series = pd.Series(
                dtype=int
            )

        event_fig = go.Figure(
            data=[
                go.Pie(
                    labels=type_series.index.tolist(),
                    values=type_series.values.tolist(),
                    hole=0.68,
                    textinfo="percent",
                    hovertemplate=(
                        "%{label}<br>"
                        "%{value}건<br>"
                        "%{percent}"
                        "<extra></extra>"
                    )
                )
            ]
        )

        dominant_type = (
            str(type_series.index[0])
            if not type_series.empty
            else "-"
        )

        event_fig.update_layout(
            title=dict(
                text="이벤트 유형 분포",
                font=dict(
                    size=15,
                    color="#e5e7eb"
                )
            ),
            annotations=[
                dict(
                    text=(
                        f"{dominant_type}"
                        "<br>"
                        "<span style='font-size:10px'>최다 유형</span>"
                    ),
                    x=0.5,
                    y=0.5,
                    showarrow=False,
                    font=dict(
                        size=18,
                        color="#f8fafc"
                    )
                )
            ],
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(
                color="#94a3b8"
            ),
            legend=dict(
                orientation="h",
                y=-0.08,
                x=0.5,
                xanchor="center"
            ),
            margin=dict(
                l=10,
                r=10,
                t=45,
                b=35
            ),
            height=330
        )

        st.plotly_chart(
            event_fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )


    # -----------------------------------------------------
    # 평균 위험도 게이지
    # -----------------------------------------------------

    with visual3:

        if "risk_score" in df.columns:

            average_risk = float(
                pd.to_numeric(
                    df["risk_score"],
                    errors="coerce"
                )
                .fillna(0)
                .mean()
            )

        else:
            average_risk = 0.0


        if average_risk >= 80:
            current_status = "심각"

        elif average_risk >= 60:
            current_status = "높음"

        elif average_risk >= 24:
            current_status = "주의"

        else:
            current_status = "낮음"


        gauge_fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=average_risk,
                number={
                    "suffix": "점",
                    "font": {
                        "size": 34,
                        "color": "#f8fafc"
                    }
                },
                title={
                    "text": (
                        "최근 이벤트 평균 위험도"
                        f"<br><span style='font-size:13px'>현재 상태: {current_status}</span>"
                    ),
                    "font": {
                        "size": 15,
                        "color": "#e5e7eb"
                    }
                },
                gauge={
                    "axis": {
                        "range": [0, 100],
                        "tickcolor": "#64748b"
                    },
                    "bar": {
                        "color": "#3b82f6",
                        "thickness": 0.25
                    },
                    "bgcolor": "#111827",
                    "borderwidth": 0,
                    "steps": [
                        {
                            "range": [0, 24],
                            "color": "#123525"
                        },
                        {
                            "range": [24, 60],
                            "color": "#3d3510"
                        },
                        {
                            "range": [60, 80],
                            "color": "#42250e"
                        },
                        {
                            "range": [80, 100],
                            "color": "#41191d"
                        }
                    ],
                    "threshold": {
                        "line": {
                            "color": "#ef4444",
                            "width": 3
                        },
                        "thickness": 0.75,
                        "value": 80
                    }
                }
            )
        )

        gauge_fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(
                color="#94a3b8"
            ),
            margin=dict(
                l=25,
                r=25,
                t=55,
                b=10
            ),
            height=330
        )

        st.plotly_chart(
            gauge_fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )


    st.caption(
        "※ 현재 화면의 시각화는 최근 로딩된 이벤트를 기준으로 계산됩니다."
    )


    # =====================================================
    # 즉시 확인 필요
    # =====================================================

    section_header(
        "즉시 확인 필요"
    )

    priority_left, priority_right = st.columns(
        [1.15, 1]
    )


    # -----------------------------------------------------
    # 고위험 이벤트 TOP 5
    # -----------------------------------------------------

    with priority_left:

        st.markdown(
            "**위험도 상위 이벤트 5건**"
        )

        if (
            "risk_score" in df.columns
            and not df.empty
        ):

            top_events = (
                df.sort_values(
                    "risk_score",
                    ascending=False
                )
                .head(5)
                .copy()
            )

            top_event_columns = [
                column
                for column in [
                    "timestamp",
                    "user",
                    "event_type",
                    "risk_score",
                    "risk_level"
                ]
                if column in top_events.columns
            ]

            top_events = top_events[
                top_event_columns
            ].copy()

            if "event_type" in top_events.columns:
                top_events["event_type"] = (
                    top_events["event_type"]
                    .astype(str)
                    .apply(event_type_korean)
                )

            top_events = top_events.rename(
                columns={
                    "timestamp": "발생 시간",
                    "user": "사용자",
                    "event_type": "이벤트",
                    "risk_score": "위험도",
                    "risk_level": "등급"
                }
            )

            st.dataframe(
                top_events,
                use_container_width=True,
                hide_index=True,
                height=245
            )

        else:
            st.info(
                "표시할 위험 이벤트가 없습니다."
            )


    # -----------------------------------------------------
    # 위험 사용자 TOP 5
    # -----------------------------------------------------

    with priority_right:

        st.markdown(
            "**현재 위험 사용자 TOP 5**"
        )

        if (
            "user" in df.columns
            and "risk_score" in df.columns
        ):

            user_summary = (
                df.groupby("user")
                .agg(
                    최고위험도=(
                        "risk_score",
                        "max"
                    ),
                    평균위험도=(
                        "risk_score",
                        "mean"
                    ),
                    이벤트수=(
                        "risk_score",
                        "count"
                    )
                )
                .reset_index()
            )

            user_summary = (
                user_summary
                .sort_values(
                    [
                        "최고위험도",
                        "평균위험도"
                    ],
                    ascending=False
                )
                .head(5)
            )

            user_summary[
                "평균위험도"
            ] = (
                user_summary[
                    "평균위험도"
                ]
                .round(2)
            )

            user_summary = user_summary.rename(
                columns={
                    "user": "사용자"
                }
            )

            st.dataframe(
                user_summary,
                use_container_width=True,
                hide_index=True,
                height=245
            )

        else:
            st.info(
                "표시할 사용자 데이터가 없습니다."
            )


    # =====================================================
    # 행동 변화 검증 현황
    # =====================================================

    section_header(
        "행동 변화 검증 현황"
    )

    st.caption(
        "새 IP·프로세스·장치가 현재 정상 기준선에 반영 가능한 상태인지 요약합니다."
    )

    behavior_status_by_target = {}

    if "reasons" in df.columns:

        behavior_pattern = re.compile(
            r"행동 변화 검증:\s*([^/]+?)\s*/\s*"
            r"(OBSERVING|ACCEPTED|REJECTED)"
        )

        # df는 최신순 정렬 상태이므로
        # 동일 대상은 가장 최근 상태만 사용
        for reason_text in (
            df["reasons"]
            .fillna("")
            .astype(str)
        ):

            matches = behavior_pattern.findall(
                reason_text
            )

            for target, status in matches:

                target = target.strip()

                if (
                    target
                    and target
                    not in behavior_status_by_target
                ):
                    behavior_status_by_target[
                        target
                    ] = status


    observing_count = sum(
        1
        for status
        in behavior_status_by_target.values()
        if status == "OBSERVING"
    )

    accepted_count = sum(
        1
        for status
        in behavior_status_by_target.values()
        if status == "ACCEPTED"
    )

    rejected_count = sum(
        1
        for status
        in behavior_status_by_target.values()
        if status == "REJECTED"
    )


    behavior1, behavior2, behavior3 = st.columns(
        3
    )

    with behavior1:
        st.metric(
            "관찰 중",
            observing_count,
            help="아직 정상 여부를 판단하기 위해 관찰 중인 신규 행동"
        )

    with behavior2:
        st.metric(
            "정상 승인",
            accepted_count,
            help="검증을 통과해 정상 기준선 학습이 허용된 행동"
        )

    with behavior3:
        st.metric(
            "학습 제외",
            rejected_count,
            help="위험 맥락이 확인되어 정상 기준선 학습에서 제외된 행동"
        )


    if (
        observing_count
        + accepted_count
        + rejected_count
        == 0
    ):
        st.info(
            "최근 이벤트에는 행동 변화 검증 기록이 없습니다."
        )


    # =====================================================
    # 기존 주요 경보
    # =====================================================

    section_header(
        "주요 보안 경보"
    )

    render_alert_table(
        df,
        height=260
    )


    # =====================================================
    # 최근 이벤트
    # =====================================================

    section_header(
        "최근 보안 이벤트"
    )

    render_timeline(
        df.head(50),
        height=330
    )


'''

new_text = (
    text[:page1_start]
    + new_page1
    + "\n\n"
    + text[page2_start:]
)


# ---------------------------------------------------------
# 4. 백업 및 저장
# ---------------------------------------------------------

backup = Path(
    "dashboard/app.before_visual_home.py"
)

shutil.copy2(
    app,
    backup
)

app.write_text(
    new_text,
    encoding="utf-8"
)

py_compile.compile(
    str(app),
    doraise=True
)

print("[완료] 보안 현황 첫 화면 시각화 개편")
print("[백업] dashboard/app.before_visual_home.py")
print("[검사] dashboard/app_beforealert.py 문법 정상")
print("[추가] 위험 등급 도넛")
print("[추가] 이벤트 유형 도넛")
print("[추가] 평균 위험도 게이지")
print("[추가] 고위험 이벤트 / 사용자 TOP 5")
print("[추가] 행동 변화 검증 현황")
