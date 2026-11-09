from datetime import datetime, timedelta
from sqlalchemy import text

from server.database import SessionLocal
from server.main import EventCreate, process_security_event
from server.incident_engine import correlate_security_incident

TEST_USER = "__sequence_verify__"
BASE_IP = "203.0.113.77"

db = SessionLocal()

def send(label, event):
    result = process_security_event(
        event,
        db,
        perf_logging=False,
    )

    print()
    print("-" * 72)
    print(label)
    print("-" * 72)
    print(f"event_id       : {result.get('event_id')}")
    print(f"sequence_score : {result.get('sequence_score')}")
    print(f"risk_score     : {result.get('risk_score')}")
    print(f"risk_level     : {result.get('risk_level')}")
    print(f"incident_created: {result.get('incident_created')}")
    print(f"incident_updated: {result.get('incident_updated')}")

    reasons = result.get("reasons") or []
    for reason in reasons:
        if any(
            keyword in str(reason)
            for keyword in (
                "로그인 실패",
                "로그인 성공",
                "대외비",
                "USB",
                "외부 전송",
                "시퀀스",
                "Sequence",
                "계정 탈취",
                "정보 유출",
            )
        ):
            print(f" - {reason}")

    return result


try:
    # ------------------------------------------------------------
    # 이전 동일 테스트 사용자 데이터 정리
    # ------------------------------------------------------------
    for sql in (
        "DELETE FROM security_incidents WHERE user=:user",
        "DELETE FROM behavior_change_observations WHERE user=:user",
        "DELETE FROM event_context WHERE user=:user",
        "DELETE FROM security_events WHERE user=:user",
    ):
        try:
            db.execute(text(sql), {"user": TEST_USER})
            db.commit()
        except Exception:
            db.rollback()

    base = datetime.now().replace(microsecond=0)

    print("=" * 72)
    print("SENTINEL Sequence / Incident 전용 검증")
    print("=" * 72)
    print(f"테스트 사용자: {TEST_USER}")
    print("공격 흐름:")
    print("로그인 실패 3회 -> 로그인 성공 -> 대외비 접근 -> USB -> PowerShell")
    print("=" * 72)

    events = [
        (
            "[1] 로그인 실패 #1",
            EventCreate(
                user=TEST_USER,
                event_type="login_failed",
                timestamp=base,
                source="sequence_validation",
                source_ip=BASE_IP,
                login_success=0,
                login_fail_count=1,
            ),
        ),
        (
            "[2] 로그인 실패 #2",
            EventCreate(
                user=TEST_USER,
                event_type="login_failed",
                timestamp=base + timedelta(seconds=2),
                source="sequence_validation",
                source_ip=BASE_IP,
                login_success=0,
                login_fail_count=1,
            ),
        ),
        (
            "[3] 로그인 실패 #3",
            EventCreate(
                user=TEST_USER,
                event_type="login_failed",
                timestamp=base + timedelta(seconds=4),
                source="sequence_validation",
                source_ip=BASE_IP,
                login_success=0,
                login_fail_count=1,
            ),
        ),
        (
            "[4] 로그인 성공",
            EventCreate(
                user=TEST_USER,
                event_type="login_success",
                timestamp=base + timedelta(seconds=6),
                source="sequence_validation",
                source_ip=BASE_IP,
                login_success=1,
                login_fail_count=0,
            ),
        ),
        (
            "[5] 대외비 문서 접근",
            EventCreate(
                user=TEST_USER,
                event_type="file_access",
                timestamp=base + timedelta(seconds=8),
                source="sequence_validation",
                source_ip=BASE_IP,
                login_success=1,
                file_name="confidential_sequence_test.docx",
                file_path=r"C:\SIEM_TEST\confidential_sequence_test.docx",
                file_grade="대외비",
                file_access_count=1,
            ),
        ),
        (
            "[6] USB 연결",
            EventCreate(
                user=TEST_USER,
                event_type="usb_connected",
                timestamp=base + timedelta(seconds=10),
                source="sequence_validation",
                source_ip=BASE_IP,
                usb_connected=1,
                device_name="SENTINEL_TEST_USB",
                device_id="SEQ-USB-001",
            ),
        ),
        (
            "[7] 외부 전송 가능 프로세스 실행",
            EventCreate(
                user=TEST_USER,
                event_type="process_execution",
                timestamp=base + timedelta(seconds=12),
                source="sequence_validation",
                source_ip=BASE_IP,
                process_name="powershell.exe",
                command_line='powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ALQBPAHUAdABwAHUAdAAgACIAUwBFAE4AVABJAE4ARQBMAF8AVABFAFMAVAAiAA==',
                parent_process="explorer.exe",
            ),
        ),
    ]

    final_result = None

    for label, event in events:
        final_result = send(label, event)

    # ------------------------------------------------------------
    # 최종 Incident를 엔진에서 직접 한 번 더 확인
    # ------------------------------------------------------------
    incident_check = correlate_security_incident(
        db=db,
        user=TEST_USER,
        reference_time=base + timedelta(seconds=12),
    )

    incident = incident_check.get("incident")
    correlation = incident_check.get("correlation") or {}

    print()
    print("=" * 72)
    print("[최종 검증 결과]")
    print("=" * 72)
    print(f"Final Sequence Score : {final_result.get('sequence_score') if final_result else None}")
    print(f"Incident Created     : {incident_check.get('incident_created')}")
    print(f"Incident Updated     : {incident_check.get('incident_updated')}")
    print(f"Correlation Score    : {correlation.get('correlation_score')}")

    if incident:
        print(f"Incident ID          : {incident.get('id')}")
        print(f"Incident Type        : {incident.get('incident_type')}")
        print(f"Incident Severity    : {incident.get('severity')}")
        print(f"Incident Title       : {incident.get('title')}")

    stages = correlation.get("stages") or []
    if stages:
        print()
        print("연결된 공격 단계:")
        for stage in stages:
            print(
                f" - {stage.get('stage_id')}: "
                f"{stage.get('name')} "
                f"(score +{stage.get('score')})"
            )

    sequence_ok = (
        final_result is not None
        and float(final_result.get("sequence_score") or 0) > 0
    )
    incident_ok = (
        bool(incident_check.get("incident_created"))
        or bool(incident_check.get("incident_updated"))
        or incident is not None
    )

    print()
    if sequence_ok and incident_ok:
        print("[성공] 6번 기능 검증 완료: 복수 이상행동을 공격 흐름으로 연결하고 Incident를 생성/갱신했습니다.")
    else:
        print("[확인 필요] Sequence 또는 Incident 조건이 충족되지 않았습니다.")
        print("위 출력 전체를 그대로 보내주세요.")

finally:
    db.close()
