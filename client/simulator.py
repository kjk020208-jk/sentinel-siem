import time
import requests


API_URL = "http://127.0.0.1:8000/events"


def send_event(event):
    event = {
        "source": "simulator",
        **event
    }

    try:
        response = requests.post(
            API_URL,
            json=event,
            timeout=5
        )

        if response.status_code == 200:
            result = response.json()

            print("=" * 60)
            print(f"이벤트 전송 성공: {event['event_type']}")
            print(f"사용자: {event['user']}")
            print(f"Rule Score: {result['rule_score']}")
            print(f"Anomaly Score: {result['anomaly_score']}")
            print(f"Risk Score: {result['risk_score']}")
            print(f"Risk Level: {result['risk_level']}")

            if result["reasons"]:
                print("탐지 이유:")
                for reason in result["reasons"]:
                    print(f" - {reason}")

        else:
            print(
                f"전송 실패: "
                f"{response.status_code} "
                f"{response.text}"
            )

    except requests.exceptions.RequestException as error:
        print(f"서버 연결 실패: {error}")


def normal_scenario():
    print("\n[정상 사용자 시나리오 시작]\n")

    events = [
        {
            "user": "user01",
            "event_type": "login_success",
            "source_ip": "192.168.56.101",
            "login_success": 1
        },
        {
            "user": "user01",
            "event_type": "file_access",
            "source_ip": "192.168.56.101",
            "login_success": 1,
            "file_name": "meeting_notes.docx",
            "file_grade": "일반",
            "file_access_count": 3,
            "process_name": "WINWORD.EXE"
        },
        {
            "user": "user01",
            "event_type": "file_access",
            "source_ip": "192.168.56.101",
            "login_success": 1,
            "file_name": "schedule.xlsx",
            "file_grade": "일반",
            "file_access_count": 2,
            "process_name": "EXCEL.EXE"
        }
    ]

    for event in events:
        send_event(event)
        time.sleep(1)

    print("\n[정상 사용자 시나리오 종료]\n")


def attack_scenario():
    print("\n[공격 시나리오 시작]\n")

    # 로그인 실패를 각각 별도의 이벤트로 전송
    for fail_count in range(1, 6):
        event = {
            "user": "user02",
            "event_type": "login_failed",
            "source_ip": "203.0.113.50",
            "login_success": 0,
            "login_fail_count": fail_count
        }

        send_event(event)
        time.sleep(1)

    events = [
        {
            "user": "user02",
            "event_type": "login_success",
            "source_ip": "203.0.113.50",
            "login_success": 1
        },
        {
            "user": "user02",
            "event_type": "file_access",
            "source_ip": "203.0.113.50",
            "login_success": 1,
            "file_name": "customer_personal_data.docx",
            "file_grade": "대외비",
            "file_access_count": 35,
            "process_name": "WINWORD.EXE"
        },
        {
            "user": "user02",
            "event_type": "usb_connected",
            "source_ip": "203.0.113.50",
            "usb_connected": 1
        },
        {
            "user": "user02",
            "event_type": "process_execution",
            "source_ip": "203.0.113.50",
            "process_name": "chrome.exe"
        }
    ]

    for event in events:
        send_event(event)
        time.sleep(1)

    print("\n[공격 시나리오 종료]\n")


def main():
    while True:
        print("=" * 60)
        print("내부자 위협 탐지 시뮬레이터")
        print("=" * 60)
        print("1. 정상 사용자 시나리오")
        print("2. 공격 사용자 시나리오")
        print("3. 종료")

        choice = input("\n실행할 시나리오를 선택하세요: ")

        if choice == "1":
            normal_scenario()

        elif choice == "2":
            attack_scenario()

        elif choice == "3":
            print("시뮬레이터를 종료합니다.")
            break

        else:
            print("1, 2, 3 중 하나를 입력하세요.")


if __name__ == "__main__":
    main()