from datetime import datetime, timedelta

from server.models import SecurityEvent
from server.response_control_engine import ResponseControlAction


SEQUENCE_WINDOW_MINUTES = 10
USB_FILE_WINDOW_MINUTES = 30

EXTERNAL_TRANSFER_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "outlook.exe",
    "olk.exe",
    "thunderbird.exe",
    "curl.exe",
    "wget.exe",
    "powershell.exe",
    "pwsh.exe",
}

SCRIPTING_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
}

SENSITIVE_GRADES = {
    "대외비",
    "기밀",
    "비밀",
    "confidential",
    "secret",
    "restricted",
}


def _latest_completed_release_time(db, user, reference_time):
    """
    완료된 SOAR RELEASE를 이전 공격 Episode의 종료 경계로 사용한다.
    과거 이벤트는 DB에 그대로 남지만, 새 Sequence 계산에는 끌고 오지 않는다.
    """
    row = (
        db.query(ResponseControlAction)
        .filter(
            ResponseControlAction.user == user,
            ResponseControlAction.operation == "RELEASE",
            ResponseControlAction.status == "COMPLETED",
            ResponseControlAction.completed_at.isnot(None),
            ResponseControlAction.completed_at <= reference_time,
        )
        .order_by(
            ResponseControlAction.completed_at.desc(),
            ResponseControlAction.id.desc(),
        )
        .first()
    )

    return row.completed_at if row is not None else None


def _is_sensitive(event):
    grade = str(getattr(event, "file_grade", "") or "").lower().strip()
    return grade in SENSITIVE_GRADES


def _process_name(event):
    return str(getattr(event, "process_name", "") or "").lower().strip()


def analyze_sequence(db, user, reference_time=None):
    """
    Sequence Engine v2

    하나의 고정 공격 시나리오가 아니라 여러 공격 경로를 병렬 평가한다.

    대표 경로:
    1) Credential Compromise
       로그인 실패 반복 -> 로그인 성공

    2) Sensitive Data Exfiltration
       민감문서 접근 -> USB 연결
       민감문서 접근 -> 외부 전송 가능 프로세스

    3) Direct Exfiltration
       로그인 이상 없이도 민감문서 -> Chrome/PowerShell/Outlook 등

    4) USB Exfiltration
       USB 연결 -> 파일 접근

    5) Suspicious Scripting
       민감문서 접근 -> PowerShell/pwsh/cmd 등

    RELEASE 완료 이전의 과거 Episode 이벤트는 새 시퀀스 계산에서 제외한다.
    """

    if reference_time is None:
        reference_time = datetime.now()

    episode_reset_at = _latest_completed_release_time(
        db,
        user,
        reference_time,
    )

    since = reference_time - timedelta(
        minutes=SEQUENCE_WINDOW_MINUTES
    )

    if (
        episode_reset_at is not None
        and episode_reset_at > since
    ):
        since = episode_reset_at

    recent_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp > since,
            SecurityEvent.timestamp <= reference_time,
        )
        .order_by(
            SecurityEvent.timestamp.asc(),
            SecurityEvent.id.asc(),
        )
        .all()
    )

    sequence_score = 0
    reasons = []
    detected_vectors = set()

    # -------------------------------------------------
    # 공통 이벤트 집합
    # -------------------------------------------------

    failed_events = [
        event
        for event in recent_events
        if event.event_type == "login_failed"
    ]

    success_events = [
        event
        for event in recent_events
        if event.event_type == "login_success"
    ]

    sensitive_events = [
        event
        for event in recent_events
        if event.event_type == "file_access"
        and _is_sensitive(event)
    ]

    transfer_events = [
        event
        for event in recent_events
        if (
            event.event_type == "process_execution"
            and _process_name(event) in EXTERNAL_TRANSFER_PROCESSES
        )
    ]

    scripting_events = [
        event
        for event in recent_events
        if (
            event.event_type == "process_execution"
            and _process_name(event) in SCRIPTING_PROCESSES
        )
    ]

    usb_events = [
        event
        for event in recent_events
        if (
            event.event_type == "usb_connected"
            or getattr(event, "usb_connected", 0) == 1
        )
    ]

    # -------------------------------------------------
    # 1. Credential Compromise
    # 로그인 실패가 있는 경우만 적용.
    # 다른 공격 경로의 필수 조건은 아니다.
    # -------------------------------------------------

    login_failed_count = len(failed_events)

    if login_failed_count >= 3:
        sequence_score += 15
        detected_vectors.add("CREDENTIAL_COMPROMISE")
        reasons.append(
            f"최근 {SEQUENCE_WINDOW_MINUTES}분간 "
            f"로그인 실패 {login_failed_count}회"
        )

    login_success_event = None

    if login_failed_count >= 3:
        third_failed_event = failed_events[2]

        for event in success_events:
            if event.timestamp >= third_failed_event.timestamp:
                login_success_event = event
                break

    failed_then_success = login_success_event is not None

    if failed_then_success:
        sequence_score += 20
        detected_vectors.add("CREDENTIAL_COMPROMISE")
        reasons.append(
            "반복 로그인 실패 후 로그인 성공"
        )

    # -------------------------------------------------
    # 2. Sensitive Data Access
    # 로그인 이상이 없어도 민감문서 접근 자체를 독립 시그널로 본다.
    # -------------------------------------------------

    first_sensitive_event = (
        sensitive_events[0]
        if sensitive_events
        else None
    )

    if sensitive_events:
        # 단일 민감문서 접근은 중간 수준 맥락 신호.
        sequence_score += 15
        detected_vectors.add("SENSITIVE_DATA_ACCESS")
        reasons.append(
            f"민감 문서 접근 {len(sensitive_events)}건"
        )

        if len(sensitive_events) >= 3:
            sequence_score += 10
            reasons.append(
                "짧은 시간 내 민감 문서 반복 접근"
            )

    # 로그인 이상 뒤 민감문서 접근은 추가 가중.
    if failed_then_success and first_sensitive_event is not None:
        if first_sensitive_event.timestamp >= login_success_event.timestamp:
            sequence_score += 15
            detected_vectors.add("ACCOUNT_TO_DATA_ACCESS")
            reasons.append(
                "로그인 이상 징후 이후 민감 문서 접근"
            )

    # -------------------------------------------------
    # 3. Sensitive -> USB
    # 로그인 실패가 없어도 독립적으로 탐지.
    # -------------------------------------------------

    usb_after_sensitive = None

    if first_sensitive_event is not None:
        for event in usb_events:
            if event.timestamp >= first_sensitive_event.timestamp:
                usb_after_sensitive = event
                break

    if usb_after_sensitive is not None:
        sequence_score += 25
        detected_vectors.add("USB_EXFILTRATION")
        reasons.append(
            "민감 문서 접근 이후 USB 연결"
        )

    # -------------------------------------------------
    # 4. Sensitive -> External Transfer Process
    # Chrome/Outlook/PowerShell/curl 등.
    # 로그인 실패 없이도 직접 유출 경로로 인정.
    # -------------------------------------------------

    transfer_after_sensitive = None

    if first_sensitive_event is not None:
        for event in transfer_events:
            if event.timestamp >= first_sensitive_event.timestamp:
                transfer_after_sensitive = event
                break

    if transfer_after_sensitive is not None:
        process = _process_name(transfer_after_sensitive)
        sequence_score += 30
        detected_vectors.add("POTENTIAL_EXFILTRATION")
        reasons.append(
            "민감 문서 접근 이후 외부 전송 가능 프로세스 실행: "
            f"{process}"
        )

    # -------------------------------------------------
    # 5. Sensitive -> Suspicious Scripting
    # PowerShell/pwsh/cmd 등은 별도 강한 신호.
    # -------------------------------------------------

    scripting_after_sensitive = None

    if first_sensitive_event is not None:
        for event in scripting_events:
            if event.timestamp >= first_sensitive_event.timestamp:
                scripting_after_sensitive = event
                break

    if scripting_after_sensitive is not None:
        process = _process_name(scripting_after_sensitive)
        sequence_score += 20
        detected_vectors.add("SCRIPTED_EXFILTRATION")
        reasons.append(
            "민감 문서 접근 이후 스크립팅/명령 프로세스 실행: "
            f"{process}"
        )

    # -------------------------------------------------
    # 6. USB -> File Access
    # USB 연결 후 실제 파일 접근이 이어질 때 강한 맥락 신호.
    # -------------------------------------------------

    usb_since = reference_time - timedelta(
        minutes=USB_FILE_WINDOW_MINUTES
    )

    if (
        episode_reset_at is not None
        and episode_reset_at > usb_since
    ):
        usb_since = episode_reset_at

    usb_context_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp > usb_since,
            SecurityEvent.timestamp <= reference_time,
        )
        .order_by(
            SecurityEvent.timestamp.asc(),
            SecurityEvent.id.asc(),
        )
        .all()
    )

    last_usb_connect = None
    usb_followed_by_file = False

    for event in usb_context_events:
        if (
            event.event_type == "usb_connected"
            or getattr(event, "usb_connected", 0) == 1
        ):
            last_usb_connect = event

        elif (
            event.event_type == "usb_disconnected"
            and last_usb_connect is not None
        ):
            last_usb_connect = None

        elif (
            event.event_type == "file_access"
            and last_usb_connect is not None
            and event.timestamp >= last_usb_connect.timestamp
        ):
            usb_followed_by_file = True
            break

    if usb_followed_by_file:
        sequence_score += 35
        detected_vectors.add("USB_EXFILTRATION")
        reasons.append(
            f"USB 연결 후 {USB_FILE_WINDOW_MINUTES}분 이내 파일 접근"
        )

    # -------------------------------------------------
    # 7. Direct suspicious scripting
    # 민감문서가 없어도 PowerShell 등만으로는 약한 보조 신호.
    # 단독으로 사고 확정 수준까지 올리지는 않는다.
    # -------------------------------------------------

    if scripting_events and first_sensitive_event is None:
        sequence_score += 10
        detected_vectors.add("SUSPICIOUS_SCRIPTING")
        reasons.append(
            "스크립팅/명령 프로세스 실행 탐지"
        )

    # -------------------------------------------------
    # 8. 복합 공격 흐름 라벨
    # -------------------------------------------------

    if (
        failed_then_success
        and first_sensitive_event is not None
        and (
            usb_after_sensitive is not None
            or transfer_after_sensitive is not None
        )
    ):
        reasons.append(
            "계정 탈취 후 정보 유출 의심 시퀀스 탐지"
        )

    elif (
        first_sensitive_event is not None
        and (
            usb_after_sensitive is not None
            or transfer_after_sensitive is not None
        )
    ):
        reasons.append(
            "인증 이상 없이도 정보 유출 의심 시퀀스 탐지"
        )

    if detected_vectors:
        reasons.append(
            "탐지 벡터: "
            + ", ".join(sorted(detected_vectors))
        )

    sequence_score = min(
        sequence_score,
        100,
    )

    return sequence_score, reasons
