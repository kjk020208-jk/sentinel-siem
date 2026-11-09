import time
from datetime import datetime, timedelta

import requests


API_URL = "http://127.0.0.1:8000/events"

TEST_USER = "__integration_verify__"
BASE_IP = "203.0.113.88"


def send_event(label, payload):
    print()
    print("=" * 80)
    print(label)
    print("=" * 80)

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=10,
        )

        print(f"HTTP Status : {response.status_code}")

        if response.status_code != 200:
            print("응답:")
            print(response.text)
            return None

        result = response.json()

        print(f"event_id        : {result.get('event_id')}")
        print(f"sequence_score  : {result.get('sequence_score')}")
        print(f"risk_score      : {result.get('risk_score')}")
        print(f"risk_level      : {result.get('risk_level')}")
        print(f"incident_created: {result.get('incident_created')}")
        print(f"incident_updated: {result.get('incident_updated')}")

        reasons = result.get("reasons") or []

        if reasons:
            print()
            print("주요 탐지 근거:")

            keywords = (
                "로그인 실패",
                "로그인 성공",
                "대외비",
                "USB",
                "외부 전송",
                "PowerShell",
                "powershell",
                "시퀀스",
                "Sequence",
                "계정 탈취",
                "정보 유출",
                "행동 변화",
            )

            for reason in reasons:
                if any(keyword in str(reason) for keyword in keywords):
                    print(f" - {reason}")

        return result

    except requests.exceptions.ConnectionError:
        print("[실패] FastAPI 서버에 연결할 수 없습니다.")
        print("먼저 아래 명령으로 서버를 실행하세요.")
        print("uvicorn server.main:app --reload")
        return None

    except Exception as e:
        print(f"[오류] {type(e).__name__}: {e}")
        return None


def iso(dt):
    return dt.isoformat()


def main():
    base = datetime.now().replace(microsecond=0)

    print("=" * 80)
    print("SENTINEL 전체 통합 경로 검증")
    print("=" * 80)
    print(f"API       : {API_URL}")
    print(f"사용자    : {TEST_USER}")
    print()
    print("검증 경로:")
    print(
        "HTTP POST -> FastAPI -> DB -> Rule/UEBA -> "
        "Sequence -> Risk -> Incident"
    )
    print()
    print("공격 흐름:")
    print(
        "로그인 실패 3회 -> 로그인 성공 -> "
        "대외비 접근 -> USB -> PowerShell"
    )
    print("=" * 80)

    events = [
        (
            "[1] 로그인 실패 #1",
            {
                "user": TEST_USER,
                "event_type": "login_failed",
                "timestamp": iso(base),
                "source": "integration_validation",
                "source_ip": BASE_IP,
                "login_success": 0,
                "login_fail_count": 1,
            },
        ),
        (
            "[2] 로그인 실패 #2",
            {
                "user": TEST_USER,
                "event_type": "login_failed",
                "timestamp": iso(base + timedelta(seconds=2)),
                "source": "integration_validation",
                "source_ip": BASE_IP,
                "login_success": 0,
                "login_fail_count": 1,
            },
        ),
        (
            "[3] 로그인 실패 #3",
            {
                "user": TEST_USER,
                "event_type": "login_failed",
                "timestamp": iso(base + timedelta(seconds=4)),
                "source": "integration_validation",
                "source_ip": BASE_IP,
                "login_success": 0,
                "login_fail_count": 1,
            },
        ),
        (
            "[4] 로그인 성공",
            {
                "user": TEST_USER,
                "event_type": "login_success",
                "timestamp": iso(base + timedelta(seconds=6)),
                "source": "integration_validation",
                "source_ip": BASE_IP,
                "login_success": 1,
                "login_fail_count": 0,
            },
        ),
        (
            "[5] 대외비 문서 접근",
            {
                "user": TEST_USER,
                "event_type": "file_access",
                "timestamp": iso(base + timedelta(seconds=8)),
                "source": "integration_validation",
                "source_ip": BASE_IP,
                "login_success": 1,
                "file_name": "integration_confidential.docx",
                "file_path": r"C:\SIEM_TEST\integration_confidential.docx",
                "file_grade": "대외비",
                "file_access_count": 1,
            },
        ),
        (
            "[6] USB 연결",
            {
                "user": TEST_USER,
                "event_type": "usb_connected",
                "timestamp": iso(base + timedelta(seconds=10)),
                "source": "integration_validation",
                "source_ip": BASE_IP,
                "usb_connected": 1,
                "device_name": "SENTINEL_INTEGRATION_USB",
                "device_id": "INT-USB-001",
            },
        ),
        (
            "[7] PowerShell 실행",
            {
                "user": TEST_USER,
                "event_type": "process_execution",
                "timestamp": iso(base + timedelta(seconds=12)),
                "source": "integration_validation",
                "source_ip": BASE_IP,
                "process_name": "powershell.exe",
                "command_line": (
                    "powershell.exe -NoProfile "
                    "-Command \"Write-Output SENTINEL_INTEGRATION_TEST\""
                ),
                "parent_process": "explorer.exe",
            },
        ),
    ]

    results = []

    for label, payload in events:
        result = send_event(label, payload)

        if result is None:
            print()
            print("[중단] 이벤트 전송에 실패했습니다.")
            return

        results.append(result)

        time.sleep(0.3)

    print()
    print("=" * 80)
    print("[통합 검증 결과]")
    print("=" * 80)

    final = results[-1]

    sequence_score = float(final.get("sequence_score") or 0)
    risk_score = float(final.get("risk_score") or 0)
    risk_level = final.get("risk_level")

    incident_detected = any(
        bool(result.get("incident_created"))
        or bool(result.get("incident_updated"))
        for result in results
    )

    print(f"최종 Sequence Score : {sequence_score}")
    print(f"최종 Risk Score     : {risk_score}")
    print(f"최종 Risk Level     : {risk_level}")
    print(f"Incident 탐지       : {incident_detected}")

    print()
    print("단계별 Sequence Score")

    for index, result in enumerate(results, start=1):
        print(
            f"  {index}. "
            f"Sequence={result.get('sequence_score')} / "
            f"Risk={result.get('risk_score')} / "
            f"Level={result.get('risk_level')}"
        )

    sequence_ok = sequence_score >= 100
    risk_ok = risk_score >= 80
    level_ok = risk_level in ("HIGH", "CRITICAL")

    print()
    print("-" * 80)

    if sequence_ok and risk_ok and level_ok and incident_detected:
        print("[성공] SENTINEL 전체 분석 파이프라인 통합 검증 완료")
        print()
        print(
            "FastAPI 입력 -> 이벤트 저장 -> UEBA/Rule -> "
            "Sequence -> Risk -> Incident 연결이 정상 동작합니다."
        )
    else:
        print("[확인 필요] 일부 통합 조건이 충족되지 않았습니다.")

        if not sequence_ok:
            print(f" - Sequence Score 부족: {sequence_score}")

        if not risk_ok:
            print(f" - Risk Score 부족: {risk_score}")

        if not level_ok:
            print(f" - Risk Level 확인 필요: {risk_level}")

        if not incident_detected:
            print(" - Incident가 생성/갱신되지 않았습니다.")

    print("-" * 80)


if __name__ == "__main__":
    main()