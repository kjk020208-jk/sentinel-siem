from datetime import datetime, timedelta
import requests
from sqlalchemy import text

from server.database import SessionLocal
from server.extended_context_engine import ensure_context_tables

API = "http://127.0.0.1:8000"
USER = "__full_detection_test__"

def post(path, payload):
    r = requests.post(API + path, json=payload, timeout=30)
    return r.status_code, r.json()

print("=" * 76)
print("SENTINEL 확장 탐지 기능 통합 검증")
print("=" * 76)

# 1) 테스트 사용자 등록
status, body = post("/users", {
    "username": USER,
    "display_name": "확장 탐지 검증 사용자",
    "department": "TEST",
    "role": "employee",
})
if status not in (200, 409):
    raise RuntimeError(f"사용자 등록 실패: {status} {body}")

print(f"[1] 테스트 사용자 준비: HTTP {status}")

# 2) 정상 기준 접속 환경을 event_context에 직접 시드
db = SessionLocal()
try:
    ensure_context_tables(db)

    # 이전 테스트 흔적 제거
    db.execute(
        text("DELETE FROM event_context WHERE user=:user"),
        {"user": USER},
    )
    db.execute(
        text("DELETE FROM behavior_change_observations WHERE user=:user"),
        {"user": USER},
    )
    db.commit()

    now = datetime.now()

    normal_rows = [
        (now - timedelta(hours=2), "10.20.30.10"),
        (now - timedelta(hours=1), "10.20.30.11"),
    ]

    for i, (ts, ip) in enumerate(normal_rows, start=1):
        db.execute(
            text("""
                INSERT INTO event_context
                (
                    event_id, user, timestamp,
                    source_ip, network_prefix,
                    workstation_name, host, logon_type,
                    command_line, parent_process,
                    is_normal
                )
                VALUES
                (
                    :event_id, :user, :timestamp,
                    :source_ip, :network_prefix,
                    :workstation_name, :host, :logon_type,
                    NULL, NULL, 1
                )
            """),
            {
                "event_id": -900000 - i,
                "user": USER,
                "timestamp": ts,
                "source_ip": ip,
                "network_prefix": "10.20.30.0/24",
                "workstation_name": "BASE-PC",
                "host": "BASE-PC",
                "logon_type": "2",
            },
        )
    db.commit()
finally:
    db.close()

print("[2] 정상 기준 환경 시드 완료")
print("    대역       : 10.20.30.0/24")
print("    PC         : BASE-PC")
print("    LogonType  : 2")

# 3) 다른 IP 대역 + 새 PC + 다른 로그인 환경
status, body = post("/events", {
    "user": USER,
    "event_type": "login_success",
    "source_ip": "10.99.88.25",
    "login_success": 1,
    "workstation_name": "NEW-PC-01",
    "host": "NEW-PC-01",
    "logon_type": "10",
})
print("\n[3] 접속 환경 변화 탐지")
print("HTTP:", status)
for reason in body.get("reasons", []):
    if any(k in reason for k in (
        "평소 사용 대역",
        "PC·장치",
        "로그인 접속 환경",
        "NETWORK=",
        "WORKSTATION=",
        "LOGON_TYPE=",
    )):
        print("   -", reason)

# 4) 의심 명령줄
status, body = post("/events", {
    "user": USER,
    "event_type": "process_execution",
    "process_name": "powershell.exe",
    "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
    "parent_process": "cmd.exe",
    "host": "BASE-PC",
})
print("\n[4] 의심 명령 탐지")
print("HTTP:", status)
for reason in body.get("reasons", []):
    if "의심 명령" in reason:
        print("   -", reason)

# 5) 5분 내 대량 파일 접근
last = None
for i in range(20):
    status, last = post("/events", {
        "user": USER,
        "event_type": "file_access",
        "file_name": f"test_{i:02d}.txt",
        "file_access_count": 1,
        "process_name": "notepad.exe",
        "host": "BASE-PC",
    })
    if status != 200:
        raise RuntimeError(f"파일 접근 이벤트 실패 #{i+1}: {status} {last}")

print("\n[5] 5분 내 대량 파일 접근 탐지")
for reason in last.get("reasons", []):
    if "대량 파일 접근" in reason:
        print("   -", reason)

# 6) 공격 흐름 연결 여부
print("\n[6] 기존 Sequence / Incident 연결 상태")
print("Sequence Score:", last.get("sequence_score"))
print("Incident Created:", last.get("incident_created"))
print("Incident Updated:", last.get("incident_updated"))

print("\n" + "=" * 76)
print("검증 완료")
print("=" * 76)
