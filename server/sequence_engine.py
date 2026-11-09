from datetime import datetime, timedelta

from server.models import SecurityEvent


SEQUENCE_WINDOW_MINUTES = 10
USB_FILE_WINDOW_MINUTES = 30

EXTERNAL_TRANSFER_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "outlook.exe",
    "curl.exe",
    "powershell.exe",
    "pwsh.exe"
}


def analyze_sequence(db, user, reference_time=None):
    """
    최근 10분 동안 해당 사용자의 이벤트를 시간 순서대로 분석해서
    연속적인 위협 행위를 탐지한다.

    단순히 이벤트가 같은 시간 창에 존재하는지만 확인하지 않고,
    실제 발생 순서를 만족하는 경우에만 후속 시퀀스 점수를 부여한다.
    """

    if reference_time is None:
        reference_time = datetime.now()

    since = reference_time - timedelta(
        minutes=SEQUENCE_WINDOW_MINUTES
    )

    recent_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp >= since,
            SecurityEvent.timestamp <= reference_time
        )
        .order_by(
            SecurityEvent.timestamp.asc(),
            SecurityEvent.id.asc()
        )
        .all()
    )

    sequence_score = 0
    reasons = []

    # ---------------------------------
    # 1. 로그인 실패 반복
    # ---------------------------------

    failed_events = [
        event
        for event in recent_events
        if event.event_type == "login_failed"
    ]

    login_failed_count = len(failed_events)

    if login_failed_count >= 3:
        sequence_score += 15
        reasons.append(
            f"최근 {SEQUENCE_WINDOW_MINUTES}분간 "
            f"로그인 실패 {login_failed_count}회"
        )

    # ---------------------------------
    # 2. 반복 로그인 실패 이후 로그인 성공
    # ---------------------------------

    login_success_event = None

    if login_failed_count >= 3:
        third_failed_event = failed_events[2]

        for event in recent_events:
            if (
                event.event_type == "login_success"
                and event.timestamp >= third_failed_event.timestamp
            ):
                login_success_event = event
                break

    failed_then_success = (
        login_success_event is not None
    )

    if failed_then_success:
        sequence_score += 20
        reasons.append(
            "반복 로그인 실패 후 로그인 성공"
        )

    # ---------------------------------
    # 3. 로그인 이상 이후 대외비 문서 접근
    # ---------------------------------

    sensitive_file_event = None

    if failed_then_success:
        for event in recent_events:
            if (
                event.event_type == "file_access"
                and event.file_grade == "대외비"
                and event.timestamp >= login_success_event.timestamp
            ):
                sensitive_file_event = event
                break

    sensitive_after_login_anomaly = (
        sensitive_file_event is not None
    )

    if sensitive_after_login_anomaly:
        sequence_score += 25
        reasons.append(
            "로그인 이상 징후 이후 대외비 문서 접근"
        )

    # ---------------------------------
    # 4. 대외비 문서 접근 이후 USB 연결
    # ---------------------------------

    usb_event = None

    if sensitive_file_event is not None:
        for event in recent_events:
            if (
                (
                    event.event_type == "usb_connected"
                    or event.usb_connected == 1
                )
                and event.timestamp >= sensitive_file_event.timestamp
            ):
                usb_event = event
                break

    usb_after_sensitive_file = (
        usb_event is not None
    )

    if usb_after_sensitive_file:
        sequence_score += 20
        reasons.append(
            "대외비 문서 접근 이후 USB 연결"
        )

    # ---------------------------------
    # 5. 대외비 문서 접근 이후 외부 전송 가능 프로세스
    # ---------------------------------

    transfer_process_event = None

    if sensitive_file_event is not None:
        for event in recent_events:
            if (
                event.event_type == "process_execution"
                and event.process_name
                and event.process_name.lower()
                in EXTERNAL_TRANSFER_PROCESSES
                and event.timestamp >= sensitive_file_event.timestamp
            ):
                transfer_process_event = event
                break

    transfer_after_sensitive_file = (
        transfer_process_event is not None
    )

    if transfer_after_sensitive_file:
        sequence_score += 20
        reasons.append(
            "대외비 문서 접근 이후 "
            f"외부 전송 가능 프로세스 실행: "
            f"{transfer_process_event.process_name}"
        )

    # ---------------------------------
    # 6. USB 연결 이후 파일 접근
    # ---------------------------------
    # USB 연결 자체는 정상 업무에서도 흔할 수 있으므로
    # 연결 후 실제 파일 접근이 이어질 때 강한 맥락 신호로 본다.

    usb_since = reference_time - timedelta(
        minutes=USB_FILE_WINDOW_MINUTES
    )

    usb_context_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp >= usb_since,
            SecurityEvent.timestamp <= reference_time
        )
        .order_by(
            SecurityEvent.timestamp.asc(),
            SecurityEvent.id.asc()
        )
        .all()
    )

    last_usb_connect = None
    usb_followed_by_file = False

    for event in usb_context_events:
        if (
            event.event_type == "usb_connected"
            or event.usb_connected == 1
        ):
            last_usb_connect = event

        elif (
            event.event_type == "usb_disconnected"
            and last_usb_connect is not None
        ):
            # 연결이 종료되면 이후 파일 접근은 해당 USB 세션과 연결하지 않는다.
            last_usb_connect = None

        elif (
            event.event_type == "file_access"
            and last_usb_connect is not None
            and event.timestamp >= last_usb_connect.timestamp
        ):
            usb_followed_by_file = True

    if usb_followed_by_file:
        sequence_score += 35
        reasons.append(
            f"USB 연결 후 {USB_FILE_WINDOW_MINUTES}분 이내 파일 접근"
        )

    # ---------------------------------
    # 전체 공격 흐름 탐지
    # ---------------------------------

    full_attack_sequence = (
        login_failed_count >= 3
        and failed_then_success
        and sensitive_after_login_anomaly
        and usb_after_sensitive_file
        and transfer_after_sensitive_file
    )

    if full_attack_sequence:
        reasons.append(
            "계정 탈취 후 정보 유출 의심 시퀀스 탐지"
        )

    sequence_score = min(
        sequence_score,
        100
    )

    return sequence_score, reasons
