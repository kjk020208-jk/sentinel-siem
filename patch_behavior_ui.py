from pathlib import Path
import shutil
import py_compile

app = Path("dashboard/app_beforealert.py")
text = app.read_text(encoding="utf-8")

if "# Behavior Change Verification" in text:
    print("[SKIP] 이미 적용되어 있습니다.")
    raise SystemExit

anchor = text.find("reason_text = selected.get(")

if anchor == -1:
    raise RuntimeError("탐지 근거 위치를 찾지 못했습니다.")

markers = [
    "                    # -------------------------------------------------\n                    # Explainable Risk Score\n                    # -------------------------------------------------\n",
    "        # ---------------------------------------------------------\n        # Explainable Risk Score\n        # ---------------------------------------------------------\n",
]

pos = -1

for marker in markers:
    found = text.find(marker, anchor)
    if found != -1:
        pos = found
        break

if pos == -1:
    raise RuntimeError("Explainable Risk Score 위치를 찾지 못했습니다.")

block = '''
                    # -------------------------------------------------
                    # Behavior Change Verification
                    # -------------------------------------------------

                    behavior_change_items = []

                    for reason in reasons:
                        if str(reason).startswith("행동 변화 검증:"):
                            body = str(reason).replace(
                                "행동 변화 검증:",
                                "",
                                1
                            ).strip()

                            parts = [
                                part.strip()
                                for part in body.split(" / ", 2)
                            ]

                            if len(parts) >= 2:
                                behavior_change_items.append({
                                    "target": parts[0],
                                    "status": parts[1].upper(),
                                    "reason": parts[2] if len(parts) >= 3 else "-"
                                })

                    if behavior_change_items:
                        section_header("행동 변화 검증")

                        st.caption(
                            "새로운 IP·프로세스·장치를 즉시 정상 행동으로 학습하지 않고 "
                            "관찰한 뒤 정상 변화만 기준선에 반영합니다."
                        )

                        observing_count = sum(
                            1 for item in behavior_change_items
                            if item["status"] == "OBSERVING"
                        )

                        accepted_count = sum(
                            1 for item in behavior_change_items
                            if item["status"] == "ACCEPTED"
                        )

                        rejected_count = sum(
                            1 for item in behavior_change_items
                            if item["status"] == "REJECTED"
                        )

                        bc1, bc2, bc3 = st.columns(3)

                        with bc1:
                            st.metric("관찰 중", observing_count)

                        with bc2:
                            st.metric("정상 승인", accepted_count)

                        with bc3:
                            st.metric("학습 제외", rejected_count)

                        for item in behavior_change_items:
                            message = (
                                f"{item['status']} · {item['target']}\\n\\n"
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
                            "ACCEPTED = 정상 변화로 승인 · "
                            "REJECTED = 위험 맥락 확인으로 정상 기준선 학습 제외"
                        )


'''

backup = Path("dashboard/app.before_behavior_change_ui.py")
shutil.copy2(app, backup)

text = text[:pos] + block + text[pos:]
app.write_text(text, encoding="utf-8")

py_compile.compile(str(app), doraise=True)

print("[완료] dashboard/app_beforealert.py 수정")
print("[백업] dashboard/app.before_behavior_change_ui.py")
print("[검사] 문법 정상")
