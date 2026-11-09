from pathlib import Path
import shutil
import py_compile

ROOT = Path(__file__).resolve().parent

candidates = [
    ROOT / "dashboard" / "app_beforealert.py",
    ROOT / "app_beforealert.py",
    ROOT / "app_risk_receipt_final.py",
]

INSERT_MARKER = "                    # -------------------------------------------------\n                    # Explainable Risk Score\n                    # -------------------------------------------------\n"
NEW_BLOCK = "\n                    # -------------------------------------------------\n                    # Behavior Change Verification\n                    # -------------------------------------------------\n\n                    behavior_change_items = []\n\n                    for reason in reasons:\n                        if str(reason).startswith(\"행동 변화 검증:\"):\n                            body = str(reason).replace(\n                                \"행동 변화 검증:\",\n                                \"\",\n                                1\n                            ).strip()\n\n                            parts = [\n                                part.strip()\n                                for part in body.split(\" / \", 2)\n                            ]\n\n                            if len(parts) >= 2:\n                                target = parts[0]\n                                status = parts[1]\n                                decision_reason = (\n                                    parts[2]\n                                    if len(parts) >= 3\n                                    else \"-\"\n                                )\n\n                                behavior_change_items.append(\n                                    {\n                                        \"target\": target,\n                                        \"status\": status,\n                                        \"reason\": decision_reason,\n                                    }\n                                )\n\n                    if behavior_change_items:\n                        section_header(\n                            \"행동 변화 검증\"\n                        )\n\n                        st.caption(\n                            \"새로운 IP·프로세스·장치를 즉시 정상 행동으로 학습하지 않고 \"\n                            \"관찰한 뒤 정상 변화만 기준선에 반영합니다.\"\n                        )\n\n                        status_counts = {\n                            \"OBSERVING\": 0,\n                            \"ACCEPTED\": 0,\n                            \"REJECTED\": 0,\n                        }\n\n                        for item in behavior_change_items:\n                            status_key = str(\n                                item.get(\"status\", \"\")\n                            ).upper()\n\n                            if status_key in status_counts:\n                                status_counts[status_key] += 1\n\n                        change_col1, change_col2, change_col3 = st.columns(3)\n\n                        with change_col1:\n                            st.metric(\n                                \"관찰 중\",\n                                status_counts[\"OBSERVING\"]\n                            )\n\n                        with change_col2:\n                            st.metric(\n                                \"정상 승인\",\n                                status_counts[\"ACCEPTED\"]\n                            )\n\n                        with change_col3:\n                            st.metric(\n                                \"학습 제외\",\n                                status_counts[\"REJECTED\"]\n                            )\n\n                        for item in behavior_change_items:\n                            target = item.get(\"target\", \"-\")\n                            status_key = str(\n                                item.get(\"status\", \"\")\n                            ).upper()\n                            decision_reason = item.get(\"reason\", \"-\")\n\n                            if status_key == \"ACCEPTED\":\n                                st.success(\n                                    f\"ACCEPTED · {target}\\n\\n\"\n                                    f\"{decision_reason}\"\n                                )\n\n                            elif status_key == \"REJECTED\":\n                                st.error(\n                                    f\"REJECTED · {target}\\n\\n\"\n                                    f\"{decision_reason}\"\n                                )\n\n                            else:\n                                st.warning(\n                                    f\"OBSERVING · {target}\\n\\n\"\n                                    f\"{decision_reason}\"\n                                )\n\n                        st.caption(\n                            \"OBSERVING = 정상 여부 관찰 중 · \"\n                            \"ACCEPTED = 정상 변화로 승인하여 기준선 학습 허용 · \"\n                            \"REJECTED = 위험 맥락이 확인되어 정상 기준선 학습에서 제외\"\n                        )\n\n"

patched = []

for path in candidates:
    if not path.exists():
        continue

    text = path.read_text(encoding="utf-8")

    if "# Behavior Change Verification" in text:
        print(f"[SKIP] {path.relative_to(ROOT)} 이미 행동 변화 검증 UI가 있습니다.")
        patched.append(path)
        continue

    if INSERT_MARKER not in text:
        print(f"[건너뜀] {path.relative_to(ROOT)}: 삽입 위치를 찾지 못했습니다.")
        continue

    backup = path.with_name(
        path.stem + ".before_behavior_change_ui" + path.suffix
    )
    shutil.copy2(path, backup)

    text = text.replace(
        INSERT_MARKER,
        NEW_BLOCK + "\n" + INSERT_MARKER,
        1
    )

    path.write_text(text, encoding="utf-8")
    py_compile.compile(str(path), doraise=True)

    print(f"[완료] {path.relative_to(ROOT)} 수정")
    print(f"[백업] {backup.relative_to(ROOT)}")
    print(f"[검사] {path.relative_to(ROOT)} 문법 정상")
    patched.append(path)

if not patched:
    raise RuntimeError(
        "수정 가능한 대시보드 파일을 찾지 못했습니다. "
        "dashboard/app_beforealert.py 또는 app_beforealert.py 위치를 확인하세요."
    )

print()
print("[완료] 행동 변화 검증 UI 추가")
print("Streamlit을 재시작한 뒤 이벤트 모니터링에서 이벤트 하나를 선택하세요.")
