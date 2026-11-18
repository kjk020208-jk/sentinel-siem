# -*- coding: utf-8 -*-
"""SENTINEL: staged per-user Chrome terminate and web-SOAR stage 2.
Usage (project root): python patch_sentinel_progressive_web_v2.py
No deployment or process killing is performed by this patch itself.
"""
from pathlib import Path
import ast
from datetime import datetime
import shutil

ROOT = Path.cwd()
SERVER = ROOT / 'server' / 'threat_prediction_engine.py'
AGENT = ROOT.parent / 'siemuebax' / 'SENTINEL_phase2_agent' / 'client' / 'response_controller.py'
MARKER = 'SENTINEL_PROGRESSIVE_WEB_STAGE2_V2'


def once(data, a, b, name):
    n = data.count(a)
    if n != 1:
        raise RuntimeError('%s: expected one code anchor, found %s. No files were modified.' % (name, n))
    return data.replace(a, b, 1)


def patch_agent(data):
    start = data.index('def terminate_allowed_process(process_name):')
    end = data.index('\ndef process_from_action_reason(', start)
    old = data[start:end]
    replacement = '''def terminate_allowed_process(process_name, target_user=None):
    # SENTINEL_PROGRESSIVE_WEB_STAGE2_V2
    # Never use taskkill /IM: it terminates browsers in all Windows sessions.
    name = str(process_name or '').strip().lower()
    allowed = {
        'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
        'opera.exe', 'outlook.exe', 'olk.exe', 'thunderbird.exe',
    }
    if name not in allowed:
        return False, f'종료 허용 대상이 아닙니다: {name or "-"}'
    account = str(target_user or '').strip().rsplit('\\\\', 1)[-1].casefold()
    if not account:
        return False, '대상 사용자가 없어 프로세스 종료를 거부했습니다.'
    try:
        import psutil
    except ImportError:
        return False, 'psutil이 없어 사용자별 프로세스 검증을 수행할 수 없습니다.'
    selected = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                info = proc.info
                if str(info.get('name') or '').strip().lower() != name:
                    continue
                owner = str(info.get('username') or '').rsplit('\\\\', 1)[-1].casefold()
                if owner == account:
                    selected.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not selected:
            return False, f'대상 사용자({account})의 {name} 프로세스를 찾지 못했습니다.'
        terminated = []
        errors = []
        for proc in selected:
            try:
                proc.terminate()
                terminated.append(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                errors.append(str(exc))
        if not terminated:
            return False, '종료 실패: ' + '; '.join(errors)
        if errors:
            return False, f'{account}의 {name} {len(terminated)}개 종료 요청, 일부 실패: ' + '; '.join(errors)
        return True, f'{account}의 {name} 프로세스 {len(terminated)}개에 종료 요청 완료. PID: {terminated}'
    except Exception as exc:
        return False, f'사용자별 프로세스 종료 실패: {exc}'

'''
    data = data[:start] + replacement + data[end:]
    data = once(data,
        '        return terminate_allowed_process(process_name)',
        '        return terminate_allowed_process(process_name, action.get("user"))',
        'Bind termination to response action user')
    return data


def patch_backend(data):
    # The V1 web review patch must be present.
    if 'SENTINEL_WEB_SOAR_REVIEW_V1' not in data:
        raise RuntimeError('First web-SOAR V1 patch was not found. No files modified.')
    anchor = '    # Web/mail review-only control proposal. Independent evidence is required:'
    addition = '''    # SENTINEL_PROGRESSIVE_WEB_STAGE2_V2
    # New web event itself is only a file-read suspicion, so stage 2 requires
    # a high-risk DLP signal, 80% progression and 70% prediction confidence.
    # The real process kill is separately gated by an opt-in env variable and
    # user-scoped Windows agent. Stronger network control remains review-only.
    web_process_stage = bool(
        recommended_control is None
        and web_signals
        and web_high_risk
        and progress >= 80
        and confidence >= 70
        and _etype(events[-1]) in {'web_upload', 'email_send'}
        and str(getattr(events[-1], 'process_name', '') or '').strip().lower()
            in {'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
                'opera.exe', 'outlook.exe', 'olk.exe', 'thunderbird.exe'}
    )
    if web_process_stage:
        recommended_control = 'PROCESS_TERMINATE'
        evidence.append(
            '단계적 웹 DLP: 민감파일 브라우저 접근 + 높은 위험/진행도; '
            '대상 사용자 브라우저 선택적 종료 추천'
        )

'''
    data = once(data, anchor, addition + anchor, 'Add initial web process stage')
    data = once(data,
        "        'NETWORK_RESTRICT',\n    }\n\n    if (\n        AUTO_MICRO_CONTROL_ENABLED",
        "        'NETWORK_RESTRICT',\n        'PROCESS_TERMINATE',\n    }\n\n    if (\n        AUTO_MICRO_CONTROL_ENABLED",
        'Permit process terminate as an auto control type')
    data = once(data,
        "        and not web_review_only\n        and recommended_control in auto_control_types",
        "        and not web_review_only\n        and (recommended_control != 'PROCESS_TERMINATE' or os.getenv('SENTINEL_AUTO_WEB_PROCESS_TERMINATE', 'false').strip().lower() in {'1','true','yes','on'})\n        and recommended_control in auto_control_types",
        'Explicit opt-in to automatic web-process termination')
    data = once(data,
        "                f' · control={recommended_control}'\n                f' · stage={stage}'",
        "                f' · control={recommended_control}'\n                f' · process={str(getattr(web_signals[-1], 'process_name', '') or '').strip().lower() if recommended_control == 'PROCESS_TERMINATE' and web_signals else '-'}'\n                f' · stage={stage}'",
        'Pass exact browser name to existing response controller')
    # When feature switch is off, do not show an actionable proposal whose
    # process control may be unsafe until the scoped agent is deployed.
    return data


def main():
    if not SERVER.is_file():
        raise SystemExit(f'MISSING backend: {SERVER}')
    if not AGENT.is_file():
        raise SystemExit(f'MISSING agent: {AGENT} (find your real agent path before proceeding)')
    sources = [(AGENT, AGENT.read_text(encoding='utf-8-sig')), (SERVER, SERVER.read_text(encoding='utf-8-sig'))]
    if any(MARKER in content for _, content in sources):
        raise SystemExit('ALREADY PATCHED: stage2 marker detected. No changes made.')
    # Transform and parse both completely before touching anything.
    candidates = [(AGENT, patch_agent(sources[0][1])), (SERVER, patch_backend(sources[1][1]))]
    for path, code in candidates:
        ast.parse(code, filename=str(path))
    now = datetime.now().strftime('%Y%m%d_%H%M%S')
    backups = []
    try:
        for path, _ in candidates:
            b = path.with_name(path.name + '.before_progressive_web_' + now + '.bak')
            shutil.copy2(path, b)
            backups.append((path, b))
        for path, code in candidates:
            path.write_text(code, encoding='utf-8')
    except Exception:
        for path, backup in backups:
            shutil.copy2(backup, path)
        raise
    print('SUCCESS: staged web SOAR / user-specific process termination patch applied.')
    for path, backup in backups:
        print('Updated:', path)
        print('Backup: ', backup)
    print('NO deployment, browser termination, or live control has occurred.')
    print('New opt-in flag: SENTINEL_AUTO_WEB_PROCESS_TERMINATE=true')
    print('Deploy the agent fix BEFORE enabling the flag and deploying the backend change.')

if __name__ == '__main__':
    main()
