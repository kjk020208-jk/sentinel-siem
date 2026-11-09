from pathlib import Path
import shutil
import py_compile

app = Path("dashboard/app_beforealert.py")
text = app.read_text(encoding="utf-8")

if "# Behavior Change Verification Dashboard" in text:
    print("[SKIP] 이미 적용되어 있습니다.")
    raise SystemExit

markers = [
    """        # ---------------------------------------------------------
        # Explainable Risk Score
        # ---------------------------------------------------------
""",
    """        section_header("Explainable Risk Score")
""",
]

pos = -1

for marker in markers:
    found = text.find(marker)
    if found != -1:
        pos = found
        break

if pos == -1:
    raise RuntimeError("Explainable Risk Score 영역을 찾지 못했습니다.")

block = '''
        # ---------------------------------------------------------
        # Behavior Change Verification Dashboard
        # ---------------------------------------------------------

        section_header("행동 변화 검증")

        st.caption(
            "새로운 IP·프로세스·장치를 즉시 정상으로 학습하지 않고 "
            "관찰 후 ACCEPTED 또는 REJECTED 상태로 판정합니다."
        )

        behavior_source = filtered_df.copy()

        behavior_source = behavior_source[
            behavior_source["reasons"]
            .fillna("")
            .astype(str)
            .str.contains(
                "행동 변화 검증:",
                regex=False
            )
        ]

        if behavior_source.empty:
            st.info(
                "현재 표시 중인 이벤트에는 행동 변화 검증 결과가 없습니다."
            )

        else:
            behavior_source = behavior_source.sort_values(
                "timestamp",
                ascending=False
            )

            behavior_options = behavior_source["id"].tolist()

            behavior_labels = {}

            for _, row in behavior_source.iterrows():
                event_id = int(row["id"])

                behavior_labels[event_id] = (
                    f"#{event_id} · "
                    f"{display_value(row.get('user'))} · "
                    f"{event_type_korean(row.get('event_type'))} · "
                    f"{display_value(row.get('risk_level'))}"
                )

            selected_behavior_event_id = st.selectbox(
                "행동 변화 검증 이벤트",
                behavior_options,
                format_func=lambda event_id: behavior_labels.get(
                    event_id,
                    str(event_id)
                ),
                key="behavior_change_event_selector"
            )

            selected_behavior_row = behavior_source[
                behavior_source["id"]
                == selected_behavior_event_id
            ].iloc[0]

            behavior_reason_text = str(
                selected_behavior_row.get(
                    "reasons",
                    ""
                )
                or ""
            )

            behavior_items = []

            for reason in behavior_reason_text.split(","):
                reason = reason.strip()

                if not reason.startswith("행동 변화 검증:"):
                    continue

                body = reason.replace(
                    "행동 변화 검증:",
                    "",
                    1
                ).strip()

                parts = [
                    part.strip()
                    for part in body.split(" / ", 2)
                ]

                if len(parts) >= 2:
                    behavior_items.append({
                        "target": parts[0],
                        "status": parts[1].upper(),
                        "reason": (
                            parts[2]
                            if len(parts) >= 3
                            else "-"
                        )
                    })

            observing_count = sum(
                1
                for item in behavior_items
                if item["status"] == "OBSERVING"
            )

            accepted_count = sum(
                1
                for item in behavior_items
                if item["status"] == "ACCEPTED"
            )

            rejected_count = sum(
                1
                for item in behavior_items
                if item["status"] == "REJECTED"
            )

            bc1, bc2, bc3 = st.columns(3)

            with bc1:
                st.metric(
                    "관찰 중",
                    observing_count
                )

            with bc2:
                st.metric(
                    "정상 승인",
                    accepted_count
                )

            with bc3:
                st.metric(
                    "학습 제외",
                    rejected_count
                )

            for item in behavior_items:
                message = (
                    f"{item['status']} · "
                    f"{item['target']}\\n\\n"
                    f"{item['reason']}"
                )

                if item["status"] == "REJECTED":
                    st.error(message)

                elif item["status"] == "ACCEPTED":
                    st.success(message)

                else:
                    st.warning(message)

            st.caption(
                "OBSERVING = 정상 여부 관찰 중 · "
                "ACCEPTED = 정상 변화로 승인하여 기준선 학습 허용 · "
                "REJECTED = 위험 맥락 확인으로 정상 기준선 학습 제외"
            )


'''

backup = Path(
    "dashboard/app.before_behavior_change_dashboard.py"
)

shutil.copy2(
    app,
    backup
)

text = (
    text[:pos]
    + block
    + text[pos:]
)

app.write_text(
    text,
    encoding="utf-8"
)

py_compile.compile(
    str(app),
    doraise=True
)

print("[완료] dashboard/app_beforealert.py 수정")
print("[백업] dashboard/app.before_behavior_change_dashboard.py")
print("[검사] 문법 정상")
print("[적용] 행동 변화 검증 대시보드 추가")
