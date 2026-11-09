import argparse
import sys
from datetime import datetime, timedelta

import requests


API_URL = "http://127.0.0.1:8000"

REAL_DEMO_USER = {
    "username": "siem_demo",
    "display_name": "발표 시연 사용자",
    "department": "개발팀",
    "role": "일반 사용자",
}

VIRTUAL_USERS = [
    {
        "username": "user01",
        "display_name": "개발팀 사용자",
        "department": "개발팀",
        "role": "개발자",
        "patterns": [
            ("process_execution", "Code.exe"),
            ("process_execution", "git.exe"),
            ("process_execution", "chrome.exe"),
            ("process_execution", "notepad.exe"),
        ],
    },
    {
        "username": "user02",
        "display_name": "인사팀 사용자",
        "department": "인사팀",
        "role": "HR",
        "patterns": [
            ("process_execution", "EXCEL.EXE"),
            ("process_execution", "WINWORD.EXE"),
            ("process_execution", "chrome.exe"),
            ("file_access", "employee_list.xlsx"),
        ],
    },
    {
        "username": "user03",
        "display_name": "재무팀 사용자",
        "department": "재무팀",
        "role": "Finance",
        "patterns": [
            ("process_execution", "EXCEL.EXE"),
            ("process_execution", "AcroRd32.exe"),
            ("process_execution", "chrome.exe"),
            ("file_access", "monthly_report.xlsx"),
        ],
    },
    {
        "username": "user04",
        "display_name": "영업팀 사용자",
        "department": "영업팀",
        "role": "Sales",
        "patterns": [
            ("process_execution", "OUTLOOK.EXE"),
            ("process_execution", "chrome.exe"),
            ("process_execution", "POWERPNT.EXE"),
            ("file_access", "sales_plan.pptx"),
        ],
    },
    {
        "username": "admin01",
        "display_name": "IT 관리자",
        "department": "IT운영팀",
        "role": "Administrator",
        "patterns": [
            ("process_execution", "powershell.exe"),
            ("process_execution", "cmd.exe"),
            ("process_execution", "mmc.exe"),
            ("process_execution", "mstsc.exe"),
        ],
    },
]

TEST_USERS = [
    "__perf_verify__",
    "__integration_verify__",
    "__sequence_verify__",
    "__change_verify_demo__",
    "__full_detection_test__",
    "__risk_receipt_demo__",
]

DEFAULT_IPS = {
    "siem_demo": "127.0.0.1",
    "user01": "10.10.10.21",
    "user02": "10.10.20.31",
    "user03": "10.10.30.41",
    "user04": "10.10.40.51",
    "admin01": "10.10.50.10",
}

DEFAULT_WORKSTATIONS = {
    "siem_demo": "DESKTOP-RIG50RH",
    "user01": "DEV-PC-01",
    "user02": "HR-PC-01",
    "user03": "FIN-PC-01",
    "user04": "SALES-PC-01",
    "admin01": "ADMIN-PC-01",
}


def api_request(method, path, **kwargs):
    try:
        response = requests.request(
            method,
            f"{API_URL}{path}",
            timeout=30,
            **kwargs,
        )
        return response
    except requests.RequestException as error:
        print(f"[오류] {method} {path}: {error}")
        return None


def ensure_user(user):
    response = api_request(
        "POST",
        "/users",
        json={
            "username": user["username"],
            "display_name": user.get("display_name"),
            "department": user.get("department"),
            "role": user.get("role"),
        },
    )

    if response is None:
        return False

    if response.status_code == 200:
        print(f"[등록] {user['username']}")
        return True

    if response.status_code == 409:
        enable = api_request(
            "POST",
            f"/users/{user['username']}/enable",
        )
        if enable is not None and enable.status_code == 200:
            print(f"[기존] {user['username']} / 활성화 확인")
            return True

    print(
        f"[오류] 사용자 등록 실패 {user['username']}: "
        f"{response.status_code} {response.text[:200]}"
    )
    return False


def delete_test_user(username):
    response = api_request(
        "DELETE",
        f"/users/{username}",
    )

    if response is None:
        return

    if response.status_code == 200:
        print(f"[삭제] 테스트 사용자 {username}")
        return

    if response.status_code in (404, 400):
        print(f"[건너뜀] 테스트 사용자 없음 {username}")
        return

    print(
        f"[주의] 사용자 삭제 실패 {username}: "
        f"{response.status_code}"
    )


def send_event(payload):
    response = api_request(
        "POST",
        "/events",
        json=payload,
    )

    if response is None:
        return False

    if response.status_code != 200:
        print(
            f"[실패] {payload['user']} / "
            f"{payload['event_type']} / "
            f"{response.status_code} / "
            f"{response.text[:200]}"
        )
        return False

    return True


def make_process_event(
    username,
    timestamp,
    process_name,
):
    return {
        "user": username,
        "event_type": "process_execution",
        "timestamp": timestamp.isoformat(),
        "host": DEFAULT_WORKSTATIONS[username],
        "source": "presentation_seed",
        "raw_event_id": (
            f"PRES-{username}-PROC-"
            f"{int(timestamp.timestamp() * 1000)}"
        ),
        "source_ip": DEFAULT_IPS[username],
        "login_success": 1,
        "login_fail_count": 0,
        "file_access_count": 0,
        "usb_connected": 0,
        "process_name": process_name,
        "workstation_name": DEFAULT_WORKSTATIONS[username],
        "logon_type": "2",
        "command_line": process_name,
        "parent_process": "explorer.exe",
    }


def make_file_event(
    username,
    timestamp,
    file_name,
):
    return {
        "user": username,
        "event_type": "file_access",
        "timestamp": timestamp.isoformat(),
        "host": DEFAULT_WORKSTATIONS[username],
        "source": "presentation_seed",
        "raw_event_id": (
            f"PRES-{username}-FILE-"
            f"{int(timestamp.timestamp() * 1000)}"
        ),
        "source_ip": DEFAULT_IPS[username],
        "login_success": 1,
        "login_fail_count": 0,
        "file_access_count": 1,
        "usb_connected": 0,
        "file_name": file_name,
        "file_path": (
            f"C:\\PRESENTATION_NORMAL\\{file_name}"
        ),
        "file_grade": "일반",
        "workstation_name": DEFAULT_WORKSTATIONS[username],
        "logon_type": "2",
    }


def seed_virtual_user(user, events_per_user):
    username = user["username"]
    patterns = user["patterns"]

    base_time = (
        datetime.now()
        - timedelta(
            minutes=events_per_user + 10
        )
    )

    success = 0

    for index in range(events_per_user):
        event_type, value = (
            patterns[index % len(patterns)]
        )

        timestamp = (
            base_time
            + timedelta(
                seconds=index * 20
            )
        )

        if event_type == "process_execution":
            payload = make_process_event(
                username,
                timestamp,
                value,
            )
        else:
            payload = make_file_event(
                username,
                timestamp,
                value,
            )

        if send_event(payload):
            success += 1

        if (index + 1) % 10 == 0:
            print(
                f"  {username}: "
                f"{index + 1}/{events_per_user}"
            )

    print(
        f"[완료] {username}: "
        f"{success}/{events_per_user} 정상 이벤트"
    )


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL 발표용 데이터셋 초기 구성"
    )

    parser.add_argument(
        "--events-per-user",
        type=int,
        default=30,
        help="가상 사용자당 정상 이벤트 수 (기본 30)",
    )

    parser.add_argument(
        "--keep-test-users",
        action="store_true",
        help="기존 __test__ 계정을 삭제하지 않음",
    )

    args = parser.parse_args()

    if args.events_per_user < 4:
        print(
            "[오류] --events-per-user는 "
            "4 이상으로 설정하세요."
        )
        sys.exit(1)

    print("=" * 72)
    print("SENTINEL 발표용 데이터셋 구성")
    print("=" * 72)

    print()
    print("[1] 발표용 실제 사용자 준비")
    if not ensure_user(REAL_DEMO_USER):
        sys.exit(1)

    print()
    print("[2] 가상 조직 사용자 준비")
    for user in VIRTUAL_USERS:
        if not ensure_user(user):
            sys.exit(1)

    if not args.keep_test_users:
        print()
        print("[3] 검증용 사용자 정리")
        print(
            "주의: DELETE /users 동작은 현재 서버 구현에 따라 "
            "사용자 등록만 삭제할 수 있으며, 과거 이벤트가 남을 수도 있습니다."
        )

        for username in TEST_USERS:
            delete_test_user(username)
    else:
        print()
        print("[3] 검증용 사용자 유지")

    print()
    print("[4] 가상 사용자 정상 Baseline 데이터 생성")

    for user in VIRTUAL_USERS:
        seed_virtual_user(
            user,
            args.events_per_user,
        )

    print()
    print("=" * 72)
    print("[완료]")
    print("=" * 72)
    print(
        "실제 발표 사용자 : siem_demo "
        "(실제 Windows/Collector 시연용)"
    )
    print(
        "가상 조직 사용자 : "
        "user01 / user02 / user03 / user04 / admin01"
    )
    print(
        "가상 사용자는 정상 업무 이벤트만 생성했습니다."
    )
    print(
        "이제 siem_demo의 실제 Windows 행동으로 정상 Baseline을 "
        "형성한 뒤 공격 시나리오를 시연하세요."
    )
    print()
    print(
        "권장 실행:"
    )
    print(
        "  python setup_presentation_data.py "
        "--events-per-user 30"
    )


if __name__ == "__main__":
    main()
