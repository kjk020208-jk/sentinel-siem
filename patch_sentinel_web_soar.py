# -*- coding: utf-8 -*-
"""SENTINEL web/email DLP -> predictive SOAR review-only patch.
Run from project root on Windows using the project's Python interpreter.
No automatic network restriction is introduced for web/email signals.
"""
from pathlib import Path
from datetime import datetime
import py_compile
import shutil
import sys

src = Path('server/threat_prediction_engine.py')
if not src.is_file():
    raise SystemExit(f'NOT FOUND: {src.resolve()} (run from siemueba project root)')
original = src.read_text(encoding='utf-8-sig')
MARKER = '# SENTINEL_WEB_SOAR_REVIEW_V1'
if MARKER in original:
    raise SystemExit('Already patched (SENTINEL_WEB_SOAR_REVIEW_V1). No changes made.')

changes = []
def replace_once(text, before, after, name):
    count = text.count(before)
    if count != 1:
        raise RuntimeError(f'{name}: expected exactly 1 anchor, found {count}. Source unchanged.')
    changes.append(name)
    return text.replace(before, after, 1)

updated = original
updated = replace_once(
    updated,
    "    sensitive = [e for e in events if _etype(e) in FILE_TYPES and _is_sensitive(e) and (first_success is None or e.timestamp >= first_success)]",
    "    sensitive = [e for e in events if _etype(e) in (FILE_TYPES | {'web_upload', 'email_send'}) and _is_sensitive(e) and (first_success is None or e.timestamp >= first_success)]",
    'Include web/email signals as sensitive data access',
)
updated = replace_once(
    updated,
    "    procs = [e for e in events if _is_suspicious_process(e) and (first_usb is None or e.timestamp >= first_usb)]\n",
    """    procs = [e for e in events if _is_suspicious_process(e) and (first_usb is None or e.timestamp >= first_usb)]

    # SENTINEL_WEB_SOAR_REVIEW_V1
    # Browser/mail client reading a confidential file is only upload/attachment
    # suspicion, NOT proof that data left the endpoint.
    web_signals = [
        e for e in events
        if _etype(e) in {'web_upload', 'email_send'} and _is_sensitive(e)
    ]
    first_web_time = web_signals[0].timestamp if web_signals else None
    web_followup_procs = [
        e for e in events
        if first_web_time is not None
        and _is_suspicious_process(e)
        and e.timestamp > first_web_time
    ]
    web_high_risk = any(
        float(getattr(e, 'risk_score', 0) or 0) >= 80
        for e in web_signals
    )
""",
    'Extract time-ordered web + process evidence',
)
updated = replace_once(
    updated,
    "    if sensitive and usb:\n        stage, progress, vector = 'DEVICE_PREPARATION', 85, 'USB_EXFILTRATION'",
    """    # WEB is an independent path from USB. It always starts with observation.
    if web_signals and not usb:
        stage, progress, vector = 'WEB_UPLOAD_SUSPECTED', max(progress, 72), 'WEB_EXFILTRATION'
    if web_signals and web_followup_procs and not usb:
        stage, progress, vector = 'WEB_EXFILTRATION_REVIEW', max(progress, 84), 'WEB_EXFILTRATION'
    if sensitive and usb:
        stage, progress, vector = 'DEVICE_PREPARATION', 85, 'USB_EXFILTRATION'""",
    'Independent web threat stage and progression',
)
updated = replace_once(
    updated,
    "    if progress < 40 and recommended_control is None:",
    """    # Web/mail review-only control proposal. Independent evidence is required:
    # high-risk DLP signal + later suspicious process + failed-logon episode
    # or sequence evidence. Never auto-queue a network block on this path.
    web_review_only = bool(
        recommended_control is None
        and web_signals
        and web_followup_procs
        and web_high_risk
        and (float(sequence_score or 0) >= 40 or failure_count >= 3)
        and progress >= 80
    )
    if web_review_only:
        recommended_control = 'NETWORK_RESTRICT'
        evidence.append(
            '웹/메일 민감파일 접근 의심 + 후속 프로세스 및 독립 증거: '
            '관리자 검토용 제어 추천 (자동 실행 금지)'
        )

    if progress < 40 and recommended_control is None:""",
    'Web administrator-approval-only proposal gate',
)
updated = replace_once(
    updated,
    "        AUTO_MICRO_CONTROL_ENABLED\n        and recommended_control in auto_control_types",
    "        AUTO_MICRO_CONTROL_ENABLED\n        and not web_review_only\n        and recommended_control in auto_control_types",
    'Block automatic execution of web review proposal',
)

# Verify the complete candidate syntax before changing the original source.
import ast
ast.parse(updated, filename=str(src))
backup = src.with_name(src.name + '.before_web_soar_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '.bak')
shutil.copy2(src, backup)
try:
    src.write_text(updated, encoding='utf-8')
    py_compile.compile(str(src), doraise=True)
except Exception:
    shutil.copy2(backup, src)
    print('Patch failed: original restored from backup.', file=sys.stderr)
    raise
print('SUCCESS: Web/email predictive SOAR review path patched.')
print('Backup:', backup.resolve())
print('Updated:', src.resolve())
print('Changes:')
for item in changes:
    print(' -', item)
print('NOTE: No deployment was performed. Existing USB controls preserved.')
print('NOTE: The web recommendation requires administrator approval; never auto-queues.')
