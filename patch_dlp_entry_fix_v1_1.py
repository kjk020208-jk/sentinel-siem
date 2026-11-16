from pathlib import Path
import shutil
import py_compile
import sys

ROOT = Path.cwd()
MAIN = ROOT / "server" / "main.py"

if not MAIN.exists():
    print("[ERROR] server/main.py 를 찾지 못했습니다.")
    sys.exit(1)

backup = MAIN.with_name(MAIN.name + ".before_dlp_entry_fix_v1_1")
if not backup.exists():
    shutil.copy2(MAIN, backup)
    print(f"[BACKUP] {backup.relative_to(ROOT)}")

text = MAIN.read_text(encoding="utf-8")

anchor = '''    result = process_security_event(
        event,
        db
    )
'''

if "entry_dlp_signal = None" not in text:
    if anchor not in text:
        raise RuntimeError("/events 의 process_security_event 호출 위치를 찾지 못했습니다.")

    injected = '''    # -------------------------------------------------
    # DLP entry-point detection
    # -------------------------------------------------
    # Collector가 보낸 4663 민감파일 접근에서 실제 파일을 읽은
    # 프로세스가 브라우저/메일 클라이언트라면 업로드/첨부 시도로 승격한다.
    entry_dlp_signal = None

    _event_type = str(
        event.event_type or ""
    ).lower().strip()

    _file_grade = str(
        event.file_grade or ""
    ).lower().strip()

    _process_name = str(
        event.process_name or ""
    ).lower().strip()

    _sensitive_grade = any(
        token in _file_grade
        for token in {
            "내부",
            "대외비",
            "기밀",
            "비밀",
            "confidential",
            "secret",
            "restricted",
        }
    )

    if (
        _event_type == "file_access"
        and _sensitive_grade
        and _process_name in {
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "brave.exe",
            "opera.exe",
        }
    ):
        event.event_type = "web_upload"
        entry_dlp_signal = {
            "event_type": "web_upload",
            "reason": (
                "DLP: 웹 브라우저가 민감 문서를 직접 읽음 · "
                "웹메일/클라우드 업로드 시도 의심"
            ),
        }

    elif (
        _event_type == "file_access"
        and _sensitive_grade
        and _process_name in {
            "outlook.exe",
            "olk.exe",
            "thunderbird.exe",
        }
    ):
        event.event_type = "email_send"
        entry_dlp_signal = {
            "event_type": "email_send",
            "reason": (
                "DLP: 메일 클라이언트가 민감 문서를 직접 읽음 · "
                "외부 메일 첨부/전송 시도 의심"
            ),
        }

    result = process_security_event(
        event,
        db
    )

    # 직접적인 DLP 증거는 저장 결과도 CRITICAL로 보장한다.
    if entry_dlp_signal:
        _event_id = result.get("event_id")

        if _event_id:
            _stored_event = (
                db.query(SecurityEvent)
                .filter(
                    SecurityEvent.id == _event_id
                )
                .first()
            )

            if _stored_event is not None:
                _stored_event.event_type = (
                    entry_dlp_signal["event_type"]
                )

                if float(
                    _stored_event.risk_score or 0
                ) < 88.0:
                    _stored_event.risk_score = 88.0

                _stored_event.risk_level = "CRITICAL"

                _dlp_reason = entry_dlp_signal[
                    "reason"
                ]

                _old_reasons = str(
                    _stored_event.reasons or ""
                )

                if _dlp_reason not in _old_reasons:
                    _stored_event.reasons = (
                        f"{_old_reasons}, {_dlp_reason}"
                        if _old_reasons
                        else _dlp_reason
                    )

                db.commit()
                db.refresh(_stored_event)

                result["risk_score"] = float(
                    _stored_event.risk_score
                )
                result["risk_level"] = (
                    _stored_event.risk_level
                )
                result["event_type"] = (
                    _stored_event.event_type
                )

'''
    text = text.replace(anchor, injected, 1)
    print("[PATCH] /events DLP direct detection added")
else:
    print("[SKIP] /events DLP direct detection already present")

MAIN.write_text(text, encoding="utf-8")
py_compile.compile(str(MAIN), doraise=True)
print("[COMPILE OK] server/main.py")

print()
print("=" * 80)
print("SENTINEL DLP Entry Fix v1.1 applied")
print("=" * 80)
print("Expected:")
print("  대외비 + chrome.exe  -> web_upload / CRITICAL / Risk >= 88")
print("  대외비 + outlook.exe -> email_send / CRITICAL / Risk >= 88")
print()
print("Next:")
print("  git add server/main.py")
print('  git commit -m "Fix DLP detection on event ingestion"')
print("  git push")
