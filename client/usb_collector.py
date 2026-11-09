import time
import os

import requests
import subprocess
import win32ts


API_URL = "http://127.0.0.1:8000/events"
POLL_INTERVAL = 3
HOST_NAME = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME")


# ============================================================
# 현재 활성 Windows 사용자 조회
# ============================================================

def get_active_user():
    try:
        # 현재 실제로 활성화되어 있는
        # 콘솔 세션 ID 조회
        session_id = (
            win32ts.WTSGetActiveConsoleSessionId()
        )

        if session_id == 0xFFFFFFFF:
            return "UNKNOWN"

        # 해당 세션의 사용자 이름 조회
        user = win32ts.WTSQuerySessionInformation(
            None,
            session_id,
            win32ts.WTSUserName
        )

        if not user:
            return "UNKNOWN"

        return user.strip()

    except Exception as error:
        print(
            f"[활성 사용자 조회 실패] {error}"
        )

        return "UNKNOWN"


# ============================================================
# 현재 연결된 USB 저장장치 조회
# ============================================================

def get_usb_storage_devices():
    powershell_command = r"""
Get-PnpDevice -PresentOnly |
Where-Object {
    $_.Class -eq 'DiskDrive' -and
    $_.InstanceId -like 'USBSTOR*'
} |
ForEach-Object {
    "$($_.FriendlyName)|$($_.InstanceId)"
}
"""

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                powershell_command
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        devices = {}

        for line in result.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            parts = line.split(
                "|",
                1
            )

            if len(parts) != 2:
                continue

            friendly_name = (
                parts[0].strip()
            )

            instance_id = (
                parts[1].strip()
            )

            if not instance_id:
                continue

            devices[
                instance_id
            ] = friendly_name

        return devices

    except Exception as error:
        print(
            f"[USB 장치 조회 실패] {error}"
        )

        return {}


# ============================================================
# SIEM 전송
# ============================================================

def send_usb_event(
    user,
    device_name,
    instance_id
):
    payload = {
        "user": user,
        "event_type": "usb_connected",
        "host": HOST_NAME,
        "source": "usb_collector",
        "raw_event_id": "USB_CONNECT",
        "source_ip": None,
        "login_success": None,
        "login_fail_count": 0,
        "file_name": None,
        "file_grade": None,
        "file_access_count": 0,
        "usb_connected": 1,
        "device_name": device_name,
        "device_id": instance_id,
        "process_name": None
    }

    try:
        response = requests.post(
            API_URL,
            json=payload,
            timeout=5
        )

        if response.status_code != 200:
            print()
            print(
                f"[SIEM 전송 실패] "
                f"{response.status_code}"
            )
            print(
                response.text
            )

            return False

        result = response.json()

        print()
        print("=" * 70)
        print("[SIEM 전송 성공]")
        print(
            f"사용자       : {user}"
        )
        print(
            "이벤트       : usb_connected"
        )
        print(
            f"장치명       : {device_name}"
        )
        print(
            f"Instance ID  : {instance_id}"
        )
        print(
            "USB Connected: 1"
        )

        print(
            f"Rule Score   : "
            f"{result.get('rule_score')}"
        )

        print(
            f"Anomaly Score: "
            f"{result.get('anomaly_score')}"
        )

        print(
            f"Baseline     : "
            f"{result.get('baseline_score', 0)}"
        )

        print(
            f"Sequence     : "
            f"{result.get('sequence_score', 0)}"
        )

        print(
            f"Risk Score   : "
            f"{result.get('risk_score')}"
        )

        print(
            f"Risk Level   : "
            f"{result.get('risk_level')}"
        )

        reasons = result.get(
            "reasons",
            []
        )

        if reasons:
            print("탐지 이유:")

            for reason in reasons:
                print(
                    f"  - {reason}"
                )

        print("=" * 70)

        return True

    except requests.exceptions.RequestException as error:
        print()
        print(
            f"[FastAPI 연결 실패] {error}"
        )

        return False


# ============================================================
# Main
# ============================================================

def main():
    startup_user = get_active_user()

    print("=" * 70)
    print("USB Storage Collector")
    print("=" * 70)
    print(
        f"현재 활성 사용자 : {startup_user}"
    )
    print(
        f"FastAPI          : {API_URL}"
    )
    print(
        f"감시 주기        : {POLL_INTERVAL}초"
    )
    print("=" * 70)

    previous_devices = (
        get_usb_storage_devices()
    )

    print()
    print(
        "USB Collector 초기화 완료"
    )

    if previous_devices:
        print()
        print(
            "현재 이미 연결되어 있는 "
            "USB 저장장치:"
        )

        for (
            instance_id,
            device_name
        ) in previous_devices.items():

            print(
                f"  - {device_name}"
            )
            print(
                f"    {instance_id}"
            )

        print()
        print(
            "현재 연결된 장치는 초기 상태로만 "
            "등록하며 SIEM에 전송하지 않습니다."
        )

    else:
        print(
            "현재 연결된 USB 저장장치 없음"
        )

    print()
    print(
        "새 USB 저장장치 연결을 기다립니다."
    )
    print(
        "USB 연결 순간의 활성 Windows "
        "사용자를 자동으로 확인합니다."
    )
    print(
        "종료하려면 Ctrl+C"
    )

    try:
        while True:
            current_devices = (
                get_usb_storage_devices()
            )

            connected_ids = (
                set(
                    current_devices.keys()
                )
                - set(
                    previous_devices.keys()
                )
            )

            removed_ids = (
                set(
                    previous_devices.keys()
                )
                - set(
                    current_devices.keys()
                )
            )

            for instance_id in connected_ids:
                device_name = (
                    current_devices[
                        instance_id
                    ]
                )

                # USB 연결 시점에 실제 활성
                # 콘솔 세션 사용자를 다시 조회
                user = get_active_user()

                print()
                print("-" * 70)
                print(
                    "[USB 저장장치 연결 감지]"
                )
                print(
                    f"활성 사용자   : {user}"
                )
                print(
                    f"장치명       : {device_name}"
                )
                print(
                    f"Instance ID  : {instance_id}"
                )
                print(
                    "판정         : "
                    "이동식 저장장치 연결"
                )
                print("-" * 70)

                if user == "UNKNOWN":
                    print(
                        "→ 활성 사용자를 확인할 수 "
                        "없어 SIEM에 전송하지 않습니다."
                    )

                    continue

                print(
                    f"→ SIEM 전송 대상: {user}"
                )

                send_usb_event(
                    user,
                    device_name,
                    instance_id
                )

            for instance_id in removed_ids:
                device_name = (
                    previous_devices[
                        instance_id
                    ]
                )

                print()
                print("-" * 70)
                print(
                    "[USB 저장장치 제거 감지]"
                )
                print(
                    f"장치명       : {device_name}"
                )
                print(
                    f"Instance ID  : {instance_id}"
                )
                print(
                    "판정         : "
                    "USB 저장장치 제거"
                )
                print("-" * 70)

                # 제거 이벤트는 현재
                # SIEM에 보내지 않음

            previous_devices = (
                current_devices
            )

            time.sleep(
                POLL_INTERVAL
            )

    except KeyboardInterrupt:
        print()
        print()
        print(
            "USB Collector를 종료합니다."
        )


if __name__ == "__main__":
    main()