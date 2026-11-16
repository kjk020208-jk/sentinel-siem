from pathlib import Path
import shutil
import py_compile
import sys

ROOT = Path.cwd()
MAIN = ROOT / "server" / "main.py"
INCIDENT = ROOT / "server" / "incident_engine.py"

for p in (MAIN, INCIDENT):
    if not p.exists():
        print(f"[ERROR] missing: {p}")
        print(r"C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.")
        sys.exit(1)

for p in (MAIN, INCIDENT):
    b = p.with_name(p.name + ".before_dlp_exfil_v1")
    if not b.exists():
        shutil.copy2(p, b)
        print(f"[BACKUP] {b.relative_to(ROOT)}")

# ============================================================
# 1) server/main.py
# ============================================================
text = MAIN.read_text(encoding="utf-8")

helper_marker = "\ndef get_risk_level(score):\n"

dlp_helpers = """
# ============================================================
# SENTINEL DLP - Sensitive file external-transfer detection
# ============================================================

DLP_WEB_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
}

DLP_MAIL_PROCESSES = {
    "outlook.exe",
    "olk.exe",
    "thunderbird.exe",
}

DLP_SENSITIVE_GRADES = {
    "내부",
    "대외비",
    "기밀",
    "비밀",
    "confidential",
    "secret",
    "restricted",
}


def _normalize_dlp_event(event):
    # Windows 4663: browser/mail client directly read a sensitive file.
    # This is treated as upload/attachment attempt evidence, not proof of
    # successful remote delivery.
    event_type = str(
        getattr(event, "event_type", "") or ""
    ).lower().strip()

    if event_type != "file_access":
        return None

    grade = str(
        getattr(event, "file_grade", "") or ""
    ).lower().strip()

    process_name = str(
        getattr(event, "process_name", "") or ""
    ).lower().strip()

    sensitive = any(
        token in grade
        for token in DLP_SENSITIVE_GRADES
    )

    if not sensitive:
        return None

    if process_name in DLP_MAIL_PROCESSES:
        event.event_type = "email_send"
        return {
            "event_type": "email_send",
            "channel": "EMAIL",
            "reason": (
                "DLP: 메일 클라이언트가 민감 문서를 직접 읽음 · "
                "외부 메일 첨부/전송 시도 의심"
            ),
        }

    if process_name in DLP_WEB_PROCESSES:
        event.event_type = "web_upload"
        return {
            "event_type": "web_upload",
            "channel": "WEB",
            "reason": (
                "DLP: 웹 브라우저가 민감 문서를 직접 읽음 · "
                "웹메일/클라우드 업로드 시도 의심"
            ),
        }

    return None


"""

if "def _normalize_dlp_event(event):" not in text:
    if helper_marker not in text:
        raise RuntimeError("get_risk_level anchor not found")
    text = text.replace(
        helper_marker,
        "\n" + dlp_helpers + "def get_risk_level(score):\n",
        1,
    )
    print("[PATCH] DLP helper added")
else:
    print("[SKIP] DLP helper already present")

if "dlp_signal = _normalize_dlp_event(event)" not in text:
    anchor_a = """    total_start = perf_counter()

    # 공개 데이터셋은 원래 발생 시각을 보존해야 시간대/행동순서 분석이 가능하다.
"""
    replace_a = """    total_start = perf_counter()

    # 4663 민감파일 접근을 외부 전송 채널 증거로 승격한다.
    dlp_signal = _normalize_dlp_event(event)

    # 공개 데이터셋은 원래 발생 시각을 보존해야 시간대/행동순서 분석이 가능하다.
"""
    if anchor_a in text:
        text = text.replace(anchor_a, replace_a, 1)
        print("[PATCH] DLP normalization added")
    else:
        anchor_b = """    total_start = perf_counter()
    now = event.timestamp or datetime.now()
"""
        replace_b = """    total_start = perf_counter()
    dlp_signal = _normalize_dlp_event(event)
    now = event.timestamp or datetime.now()
"""
        if anchor_b in text:
            text = text.replace(anchor_b, replace_b, 1)
            print("[PATCH] DLP normalization added (fallback)")
        else:
            raise RuntimeError("process_security_event start anchor not found")

reason_anchor = """    reasons = list(rule_reasons)

    if is_anomaly:
"""
if 'reasons.append(dlp_signal["reason"])' not in text:
    if reason_anchor not in text:
        raise RuntimeError("reasons anchor not found")
    text = text.replace(
        reason_anchor,
        """    reasons = list(rule_reasons)

    if dlp_signal:
        rule_score = min(
            100.0,
            float(rule_score or 0) + 55.0
        )
        reasons.append(
            dlp_signal["reason"]
        )

    if is_anomaly:
""",
        1,
    )
    print("[PATCH] DLP rule contribution added")

floor_anchor = """    final_score = round(
        min(final_score, 100),
        2
    )
"""
if "final_score = max(final_score, 88.0)" not in text:
    if floor_anchor not in text:
        raise RuntimeError("final_score anchor not found")
    text = text.replace(
        floor_anchor,
        floor_anchor + """
    # Direct browser/mail -> sensitive-file access is strong DLP evidence.
    if dlp_signal:
        final_score = max(
            final_score,
            88.0
        )

""",
        1,
    )
    print("[PATCH] DLP Event Risk floor = 88")

MAIN.write_text(text, encoding="utf-8")
py_compile.compile(str(MAIN), doraise=True)
print("[COMPILE OK] server/main.py")

# ============================================================
# 2) server/incident_engine.py
# ============================================================
text = INCIDENT.read_text(encoding="utf-8")

old_sensitive = """            event.event_type == "file_access"
            and event.file_grade
"""
new_sensitive = """            event.event_type in {
                "file_access",
                "web_upload",
                "email_send",
                "external_transfer",
            }
            and event.file_grade
"""

if old_sensitive in text:
    text = text.replace(
        old_sensitive,
        new_sensitive,
        1,
    )
    print("[PATCH] DLP event types count as sensitive access")
elif '"web_upload"' in text and "sensitive_file_event" in text:
    print("[SKIP] sensitive DLP types already present")
else:
    raise RuntimeError("sensitive_file_event condition not found")

if '"EXTERNAL_TRANSFER"' not in text:
    sort_anchor = """    stages = sorted(
        stages,
"""
    idx = text.find(sort_anchor)
    if idx < 0:
        raise RuntimeError("stages sort anchor not found")

    exfil_block = """
    external_transfer_event = None

    for event in events:
        if event.event_type in {
            "web_upload",
            "email_send",
            "external_transfer",
        }:
            external_transfer_event = event
            break

    if external_transfer_event is not None:
        channel_name = {
            "web_upload": "웹 업로드/웹메일",
            "email_send": "이메일 첨부/전송",
            "external_transfer": "외부 전송",
        }.get(
            external_transfer_event.event_type,
            "외부 전송",
        )

        stages.append(
            _stage(
                "EXTERNAL_TRANSFER",
                "민감정보 외부 전송 시도",
                (
                    f"{channel_name} 경로에서 민감 문서 접근 감지: "
                    f"{external_transfer_event.file_name or '-'} · "
                    f"프로세스 {external_transfer_event.process_name or '-'}"
                ),
                external_transfer_event,
                60,
            )
        )

        score += 60

"""
    text = text[:idx] + exfil_block + text[idx:]
    print("[PATCH] EXTERNAL_TRANSFER stage added")
else:
    print("[SKIP] EXTERNAL_TRANSFER stage already present")

if "DLP_EXTERNAL_TRANSFER" not in text:
    title_anchor = """    if (
        "SENSITIVE_ACCESS"
        in unique_stage_ids
"""
    idx = text.find(title_anchor)
    if idx < 0:
        raise RuntimeError("incident title anchor not found")

    dlp_title = """
    if {
        "SENSITIVE_ACCESS",
        "EXTERNAL_TRANSFER",
    }.issubset(
        unique_stage_ids
    ):
        incident_type = (
            "DLP_EXTERNAL_TRANSFER"
        )
        title = (
            "대외비 외부 전송 시도 감지"
        )

"""
    text = text[:idx] + dlp_title + text[idx:]
    print("[PATCH] DLP incident type/title added")

INCIDENT.write_text(text, encoding="utf-8")
py_compile.compile(str(INCIDENT), doraise=True)
print("[COMPILE OK] server/incident_engine.py")

print()
print("=" * 84)
print("SENTINEL DLP External Transfer Detection v1 installed")
print("=" * 84)
print("WEB:")
print("  sensitive 4663 + chrome/msedge/firefox/brave/opera")
print("  -> event_type WEB_UPLOAD")
print()
print("MAIL:")
print("  sensitive 4663 + outlook/olk/thunderbird")
print("  -> event_type EMAIL_SEND")
print()
print("RISK:")
print("  direct DLP evidence -> minimum Event Risk 88 / CRITICAL")
print()
print("INCIDENT:")
print("  SENSITIVE_ACCESS + EXTERNAL_TRANSFER")
print("  -> DLP_EXTERNAL_TRANSFER")
print("  -> 대외비 외부 전송 시도 감지")
print()
print("NOTE:")
print("  This means attachment/upload attempt evidence.")
print("  It does not claim confirmed remote delivery.")
