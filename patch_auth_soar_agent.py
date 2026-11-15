from pathlib import Path
import shutil
import sys
import py_compile

ROOT = Path.cwd()
AUTH = ROOT / 'server' / 'auth.py'

if not AUTH.exists():
    print('[ERROR] server/auth.py를 찾지 못했습니다.')
    print(r'프로젝트 루트 C:\Users\김재경\PycharmProjects\siemueba 에서 실행하세요.')
    sys.exit(1)

backup = AUTH.with_name('auth.py.before_soar_agent_auth')
if not backup.exists():
    shutil.copy2(AUTH, backup)
    print(f'[BACKUP] {backup.relative_to(ROOT)}')

text = AUTH.read_text(encoding='utf-8')

old = (
    '        # Agent 이벤트 수집은 기존 Agent Token 체계를 그대로 사용\n'
    '        if path == "/events" and method == "POST":\n'
    '            return await call_next(request)\n'
)

new = (
    '        # Windows Agent 요청은 각 API에서 X-Agent-Token으로 검증\n'
    '        agent_paths = (\n'
    '            path == "/events"\n'
    '            or path == "/response-controls/claim"\n'
    '            or (\n'
    '                path.startswith("/response-controls/")\n'
    '                and path.endswith("/result")\n'
    '            )\n'
    '        )\n\n'
    '        if method == "POST" and agent_paths:\n'
    '            return await call_next(request)\n'
)

if new in text:
    print('[SKIP] server/auth.py는 이미 SOAR Agent 예외가 적용되어 있습니다.')
elif old in text:
    text = text.replace(old, new, 1)
    AUTH.write_text(text, encoding='utf-8')
    print('[PATCH] server/auth.py SOAR Agent 경로 예외 추가')
else:
    print('[ERROR] 예상한 기존 인증 구문을 찾지 못했습니다.')
    sys.exit(1)

py_compile.compile(str(AUTH), doraise=True)
print('[COMPILE OK] server/auth.py')
print()
print('=' * 72)
print('SENTINEL auth.py SOAR Agent 패치 완료')
print('=' * 72)
print('허용:')
print(' - POST /events')
print(' - POST /response-controls/claim')
print(' - POST /response-controls/{id}/result')
print('나머지 경로의 관리자 세션 인증은 그대로 유지됩니다.')
