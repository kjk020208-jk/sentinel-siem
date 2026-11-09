import time
import ntpath
import os
import xml.etree.ElementTree as ET

import requests
import win32evtlog
import win32ts


API_URL = "http://127.0.0.1:8000/events"
POLL_INTERVAL = 3

# 동일 사용자 + 동일 프로세스의 4688 이벤트 재전송 제한 시간
PROCESS_COOLDOWN_SECONDS = 60

# {(user, process_name): last_sent_monotonic_time}
process_last_sent = {}

CHANNEL = "Security"
HOST_NAME = os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME")

# 4663에서 실제로 감시할 폴더
MONITORED_FOLDER = r"C:\SIEM_TEST"

# 4688 수집 정책
#
# 모든 프로세스 생성 이벤트를 전송하면 이벤트 폭주가 발생하므로
# 1) 개인별 정상 업무 패턴 학습에 의미 있는 업무 프로세스
# 2) 보안 분석에 의미 있는 프로세스
# 만 선택적으로 SIEM에 전송한다.
#
# 동일 사용자 + 동일 프로세스는 아래 60초 cooldown이 적용된다.
NORMAL_WORK_PROCESSES = {
    "code.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "notepad.exe"
}

SECURITY_ANALYSIS_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "outlook.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "curl.exe",
    "bitsadmin.exe",
    "rundll32.exe",
    "regsvr32.exe"
}

MONITORED_PROCESSES = (
    NORMAL_WORK_PROCESSES
    | SECURITY_ANALYSIS_PROCESSES
)

NAMESPACE = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


# ============================================================
# XML 값 읽기
# ============================================================

def get_xml_value(root, name):
    element = root.find(
        f".//e:EventData/e:Data[@Name='{name}']",
        NAMESPACE
    )

    if element is None:
        return None

    value = element.text

    if value in (
        None,
        "",
        "-"
    ):
        return None

    return value


def get_system_value(root, tag):
    element = root.find(
        f".//e:System/e:{tag}",
        NAMESPACE
    )

    if element is None:
        return None

    return element.text


def get_record_id(root):
    value = get_system_value(
        root,
        "EventRecordID"
    )

    if value is None:
        return 0

    try:
        return int(value)

    except ValueError:
        return 0


def get_event_id(root):
    value = get_system_value(
        root,
        "EventID"
    )

    if value is None:
        return None

    try:
        return int(value)

    except ValueError:
        return None


# ============================================================
# 제외 계정
# ============================================================

def is_ignored_user(user):
    if not user:
        return True

    ignored_users = {
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "ANONYMOUS LOGON"
    }

    if user.upper() in ignored_users:
        return True

    if user.endswith("$"):
        return True

    return False


# ============================================================
# 4624 - 로그인 성공
# ============================================================

def parse_4624(root):
    user = get_xml_value(
        root,
        "TargetUserName"
    )

    domain = get_xml_value(
        root,
        "TargetDomainName"
    )

    logon_type = get_xml_value(
        root,
        "LogonType"
    )

    source_ip = get_xml_value(
        root,
        "IpAddress"
    )

    process_name = get_xml_value(
        root,
        "ProcessName"
    )

    workstation_name = get_xml_value(
        root,
        "WorkstationName"
    )

    if is_ignored_user(user):
        return None

    allowed_logon_types = {
        "2",
        "3",
        "7",
        "10",
        "11"
    }

    if logon_type not in allowed_logon_types:
        return None

    return {
        "user": user,
        "event_type": "login_success",
        "source_ip": source_ip,
        "workstation_name": workstation_name,
        "logon_type": logon_type,
        "login_success": 1,
        "login_fail_count": 0,
        "file_access_count": 0,
        "usb_connected": 0,
        "_display": {
            "title": "4624 로그인 성공",
            "domain": domain,
            "logon_type": logon_type,
            "process_name": process_name
        }
    }


# ============================================================
# 4625 - 로그인 실패
# ============================================================

def parse_4625(root):
    user = get_xml_value(
        root,
        "TargetUserName"
    )

    domain = get_xml_value(
        root,
        "TargetDomainName"
    )

    source_ip = get_xml_value(
        root,
        "IpAddress"
    )

    logon_type = get_xml_value(
        root,
        "LogonType"
    )

    status = get_xml_value(
        root,
        "Status"
    )

    sub_status = get_xml_value(
        root,
        "SubStatus"
    )

    workstation_name = get_xml_value(
        root,
        "WorkstationName"
    )

    if is_ignored_user(user):
        return None

    return {
        "user": user,
        "event_type": "login_failed",
        "source_ip": source_ip,
        "workstation_name": workstation_name,
        "logon_type": logon_type,
        "login_success": 0,
        "login_fail_count": 1,
        "file_access_count": 0,
        "usb_connected": 0,
        "_display": {
            "title": "4625 로그인 실패",
            "domain": domain,
            "logon_type": logon_type,
            "status": status,
            "sub_status": sub_status
        }
    }


# ============================================================
# 4663 - 파일 접근
# ============================================================

def parse_4663(root):
    user = get_xml_value(
        root,
        "SubjectUserName"
    )

    domain = get_xml_value(
        root,
        "SubjectDomainName"
    )

    object_type = get_xml_value(
        root,
        "ObjectType"
    )

    object_name = get_xml_value(
        root,
        "ObjectName"
    )

    access_mask = get_xml_value(
        root,
        "AccessMask"
    )

    access_list = get_xml_value(
        root,
        "AccessList"
    )

    process_path = get_xml_value(
        root,
        "ProcessName"
    )

    process_name = None

    if process_path:
        process_name = ntpath.basename(
            process_path
        )

    if is_ignored_user(user):
        return None

    if object_type is None:
        return None

    if object_type.lower() != "file":
        return None

    if not object_name:
        return None

    normalized_object = os.path.normcase(
        os.path.normpath(object_name)
    )

    normalized_folder = os.path.normcase(
        os.path.normpath(MONITORED_FOLDER)
    )

    # C:\SIEM_TEST 바깥의 파일은 무시
    try:
        common_path = os.path.commonpath(
            [
                normalized_object,
                normalized_folder
            ]
        )

    except ValueError:
        return None

    if common_path != normalized_folder:
        return None

    # 폴더 자체 접근은 제외
    if normalized_object == normalized_folder:
        return None

    # 실제 파일 데이터 읽기만 수집
    # 0x1 = FILE_READ_DATA
    if access_mask is None:
        return None

    try:
        access_value = int(
            access_mask,
            16
        )

    except ValueError:
        return None

    # FILE_READ_DATA 비트 검사
    if not (access_value & 0x1):
        return None

    # MVP:
    # SIEM_TEST 내부 파일은 중요 문서로 간주
    file_grade = "대외비"

    return {
        "user": user,
        "event_type": "file_access",
        "source_ip": None,
        "login_success": None,
        "login_fail_count": 0,
        "file_name": object_name,
        "file_grade": file_grade,
        "file_access_count": 1,
        "usb_connected": 0,
        "process_name": process_name,
        "_display": {
            "title": "4663 중요 파일 접근",
            "domain": domain,
            "access_list": access_list,
            "access_mask": access_mask,
            "process_path": process_path
        }
    }


# ============================================================
# 현재 대화형 Windows 사용자 확인
# ============================================================

def get_active_console_user():
    try:
        session_id = win32ts.WTSGetActiveConsoleSessionId()

        if session_id == 0xFFFFFFFF:
            return None

        user = win32ts.WTSQuerySessionInformation(
            None,
            session_id,
            win32ts.WTSUserName
        )

        if not user:
            return None

        user = user.strip()

        if not user:
            return None

        return user

    except Exception:
        return None


# ============================================================
# 4688 - 프로세스 생성
# ============================================================

def parse_4688(root):
    original_user = get_xml_value(
        root,
        "SubjectUserName"
    )

    user = original_user

    domain = get_xml_value(
        root,
        "SubjectDomainName"
    )

    process_path = get_xml_value(
        root,
        "NewProcessName"
    )

    parent_process = get_xml_value(
        root,
        "ParentProcessName"
    )

    command_line = get_xml_value(
        root,
        "CommandLine"
    )

    process_name = None

    if process_path:
        process_name = ntpath.basename(
            process_path
        )

    attribution_method = "event_subject"

    # 일부 Windows 11 패키지형 앱의 4688은 실제 사용자 대신
    # DESKTOP-XXXX$ 형태의 컴퓨터 계정으로 기록될 수 있다.
    # 선택 수집 대상 프로세스에 한해서만 활성 콘솔 사용자로 보정한다.
    if (
        user
        and user.endswith("$")
        and process_name
        and process_name.lower() in MONITORED_PROCESSES
    ):
        active_user = get_active_console_user()

        if active_user:
            user = active_user
            attribution_method = "active_console_user"

    if is_ignored_user(user):
        return None

    if process_name is None:
        return None

    # 4688 이벤트 폭주 방지:
    # 모든 프로세스를 전송하지 않고 개인 업무패턴 학습 또는
    # 보안 분석에 의미 있는 프로세스만 SIEM 전송 대상으로 남긴다.
    if process_name.lower() not in MONITORED_PROCESSES:
        return None

    return {
        "user": user,
        "event_type": "process_execution",
        "source_ip": None,
        "login_success": None,
        "login_fail_count": 0,
        "file_access_count": 0,
        "usb_connected": 0,
        "process_name": process_name,

        # 4688 명령행/부모 프로세스를 실제 SIEM 분석 payload에 포함
        "command_line": command_line,
        "parent_process": parent_process,

        "_display": {
            "title": "4688 프로세스 생성",
            "domain": domain,
            "process_path": process_path,
            "parent_process": parent_process,
            "command_line": command_line,
            "original_user": original_user,
            "attribution_method": attribution_method
        }
    }


# ============================================================
# 4688 프로세스 전송 쿨다운
# ============================================================

def is_process_in_cooldown(payload):
    if payload.get("event_type") != "process_execution":
        return False

    user = (payload.get("user") or "").strip().lower()
    process_name = (payload.get("process_name") or "").strip().lower()

    if not user or not process_name:
        return False

    key = (user, process_name)
    now = time.monotonic()
    last_sent = process_last_sent.get(key)

    if (
        last_sent is not None
        and now - last_sent < PROCESS_COOLDOWN_SECONDS
    ):
        return True

    process_last_sent[key] = now

    # 장시간 실행 시 딕셔너리가 불필요하게 커지는 것을 방지
    expired_before = now - (PROCESS_COOLDOWN_SECONDS * 10)

    expired_keys = [
        item_key
        for item_key, sent_time in process_last_sent.items()
        if sent_time < expired_before
    ]

    for item_key in expired_keys:
        process_last_sent.pop(item_key, None)

    return False


# ============================================================
# XML 이벤트 분석
# ============================================================

def parse_event_xml(xml_text):
    try:
        root = ET.fromstring(
            xml_text
        )

    except ET.ParseError as error:
        print(
            f"[XML 파싱 실패] {error}"
        )

        return None, None, None

    event_id = get_event_id(
        root
    )

    record_id = get_record_id(
        root
    )

    if event_id == 4624:
        payload = parse_4624(
            root
        )

    elif event_id == 4625:
        payload = parse_4625(
            root
        )

    elif event_id == 4663:
        payload = parse_4663(
            root
        )

    elif event_id == 4688:
        payload = parse_4688(
            root
        )

    else:
        payload = None

    if payload is not None:
        # Windows 이벤트의 Computer 값을 우선 사용하고, 없으면 환경변수의 호스트명을 사용한다.
        payload["host"] = get_system_value(root, "Computer") or HOST_NAME
        payload["source"] = "windows_event_log"
        payload["raw_event_id"] = str(event_id) if event_id is not None else None

        # 원본 Windows EventRecordID는 동일 Event ID의 개별 레코드를 구분하는 값이다.
        # API 공통 스키마에는 raw_event_id를 원본 이벤트 종류로 두고,
        # 세부 Record ID는 Collector 출력에서 계속 확인한다.

        if payload.get("event_type") == "file_access":
            payload["file_path"] = payload.get("file_name")

    return (
        event_id,
        record_id,
        payload
    )


# ============================================================
# 터미널 출력 여부 결정
# ============================================================

def should_print_event(event_id, payload):
    # 로그인 성공/실패와 중요 파일 접근은 항상 출력
    if event_id in (
        4624,
        4625,
        4663
    ):
        return True

    # 4688은 선택 수집 프로세스만 출력
    if event_id == 4688:
        process_name = (
            payload.get("process_name")
            or ""
        ).lower()

        if process_name in MONITORED_PROCESSES:
            return True

        return False

    return False


# ============================================================
# 수집 대상 이벤트 출력
# ============================================================

def print_detected_event(
    event_id,
    record_id,
    payload
):
    display = payload.get(
        "_display",
        {}
    )

    print()
    print("-" * 70)

    if event_id == 4624:
        print(
            "[4624 로그인 성공]"
        )

        print(
            f"Record ID    : "
            f"{record_id}"
        )

        print(
            f"사용자       : "
            f"{payload['user']}"
        )

        print(
            f"도메인       : "
            f"{display.get('domain')}"
        )

        print(
            f"Logon Type   : "
            f"{display.get('logon_type')}"
        )

        print(
            f"Source IP    : "
            f"{payload.get('source_ip')}"
        )

        print(
            "판정         : 사용자 로그인 성공"
        )

    elif event_id == 4625:
        print(
            "[4625 로그인 실패]"
        )

        print(
            f"Record ID    : "
            f"{record_id}"
        )

        print(
            f"사용자       : "
            f"{payload['user']}"
        )

        print(
            f"도메인       : "
            f"{display.get('domain')}"
        )

        print(
            f"Logon Type   : "
            f"{display.get('logon_type')}"
        )

        print(
            f"Source IP    : "
            f"{payload.get('source_ip')}"
        )

        print(
            f"Status       : "
            f"{display.get('status')}"
        )

        print(
            f"SubStatus    : "
            f"{display.get('sub_status')}"
        )

        print(
            "판정         : 사용자 로그인 실패"
        )

    elif event_id == 4663:
        print(
            "[4663 중요 파일 접근]"
        )

        print(
            f"Record ID    : "
            f"{record_id}"
        )

        print(
            f"사용자       : "
            f"{payload['user']}"
        )

        print(
            f"파일         : "
            f"{payload.get('file_name')}"
        )

        print(
            f"문서 등급    : "
            f"{payload.get('file_grade')}"
        )

        print(
            f"Access Mask  : "
            f"{display.get('access_mask')}"
        )

        print(
            f"프로세스     : "
            f"{payload.get('process_name')}"
        )

        print(
            "판정         : 중요 파일 데이터 접근"
        )

    elif event_id == 4688:
        print(
            "[4688 분석 대상 프로세스 생성]"
        )

        print(
            f"Record ID    : "
            f"{record_id}"
        )

        print(
            f"사용자       : "
            f"{payload['user']}"
        )

        print(
            f"프로세스     : "
            f"{payload.get('process_name')}"
        )

        print(
            f"Process Path : "
            f"{display.get('process_path')}"
        )

        print(
            f"Parent       : "
            f"{display.get('parent_process')}"
        )

        print(
            f"CommandLine  : "
            f"{display.get('command_line')}"
        )

        if (
            display.get("attribution_method")
            == "active_console_user"
        ):
            print(
                f"원본 사용자  : "
                f"{display.get('original_user')}"
            )

            print(
                "사용자 귀속  : 활성 콘솔 사용자 자동 매핑"
            )

        print(
            "판정         : 개인 행동 학습 / 보안 분석 대상 프로세스 실행"
        )

    print(
        "-" * 70
    )

    print(
        f"→ SIEM 전송 대상: "
        f"{payload['user']}"
    )


# ============================================================
# FastAPI 전송
# ============================================================

def send_event(
    payload,
    show_output=True
):
    # _display는 Collector 화면 출력용 데이터이므로
    # FastAPI에는 전송하지 않는다.
    api_payload = {
        key: value
        for key, value in payload.items()
        if key != "_display"
    }

    try:
        response = requests.post(
            API_URL,
            json=api_payload,
            timeout=5
        )

        if response.status_code != 200:
            print(
                f"[전송 실패] "
                f"{response.status_code} "
                f"{response.text}"
            )

            return False

        result = response.json()

        # show_output=False인 이벤트는 전송 결과만 조용히 처리한다.
        if not show_output:
            return True

        print()
        print("=" * 70)
        print("[SIEM 전송 성공]")

        print(
            f"사용자       : "
            f"{api_payload['user']}"
        )

        print(
            f"이벤트       : "
            f"{api_payload['event_type']}"
        )

        if api_payload.get(
            "source_ip"
        ):
            print(
                f"IP           : "
                f"{api_payload.get('source_ip')}"
            )

        if api_payload.get(
            "file_name"
        ):
            print(
                f"파일         : "
                f"{api_payload.get('file_name')}"
            )

        if api_payload.get(
            "file_grade"
        ):
            print(
                f"문서 등급    : "
                f"{api_payload.get('file_grade')}"
            )

        if api_payload.get(
            "process_name"
        ):
            print(
                f"프로세스     : "
                f"{api_payload.get('process_name')}"
            )

        print(
            f"Rule Score   : "
            f"{result['rule_score']}"
        )

        print(
            f"Anomaly Score: "
            f"{result['anomaly_score']}"
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
            f"Adaptive     : "
            f"{result.get('adaptive_compensation', 0)}"
        )

        print(
            f"Adaptive 적용: "
            f"{result.get('adaptive_compensation_applied', False)}"
        )

        print(
            f"Adaptive 신뢰: "
            f"{result.get('adaptive_confidence_level', '-')}"
        )

        print(
            f"Risk Score   : "
            f"{result['risk_score']}"
        )

        print(
            f"Risk Level   : "
            f"{result['risk_level']}"
        )

        print(
            f"User Risk    : "
            f"{result.get('user_risk_score', '-')}"
        )

        print(
            f"User State   : "
            f"{result.get('user_risk_level', '-')}"
        )

        reasons = result.get(
            "reasons",
            []
        )

        if reasons:
            print(
                "탐지 이유:"
            )

            for reason in reasons:
                print(
                    f"  - {reason}"
                )

        print(
            "=" * 70
        )

        return True

    except requests.exceptions.RequestException as error:
        print(
            f"[FastAPI 연결 실패] {error}"
        )

        return False


# ============================================================
# Event ID 쿼리
# ============================================================

def build_event_query(
    last_record_id=None
):
    event_filter = (
        "(EventID=4624 or "
        "EventID=4625 or "
        "EventID=4663 or "
        "EventID=4688)"
    )

    if last_record_id is None:
        return (
            "*[System["
            f"{event_filter}"
            "]]"
        )

    return (
        "*[System["
        f"{event_filter} "
        f"and EventRecordID>{last_record_id}"
        "]]"
    )


# ============================================================
# 가장 최근 대상 이벤트 Record ID
# ============================================================

def get_current_last_record_id():
    query = build_event_query()

    query_handle = win32evtlog.EvtQuery(
        CHANNEL,
        win32evtlog.EvtQueryChannelPath
        | win32evtlog.EvtQueryReverseDirection,
        query
    )

    events = win32evtlog.EvtNext(
        query_handle,
        1
    )

    if not events:
        return 0

    xml_text = win32evtlog.EvtRender(
        events[0],
        win32evtlog.EvtRenderEventXml
    )

    root = ET.fromstring(
        xml_text
    )

    return get_record_id(
        root
    )


# ============================================================
# 최근 Record ID 일부를 겹쳐서 조회
# ============================================================

def read_events_after(
    last_record_id,
    processed_record_ids
):
    # 경계 구간 이벤트 누락 방지를 위해
    # 최근 300 Record ID를 다시 확인
    overlap_start = max(
        0,
        last_record_id - 300
    )

    query = build_event_query(
        overlap_start
    )

    query_handle = win32evtlog.EvtQuery(
        CHANNEL,
        win32evtlog.EvtQueryChannelPath,
        query
    )

    new_events = []

    while True:
        try:
            events = win32evtlog.EvtNext(
                query_handle,
                100
            )

        except Exception:
            break

        if not events:
            break

        for event_handle in events:
            try:
                xml_text = win32evtlog.EvtRender(
                    event_handle,
                    win32evtlog.EvtRenderEventXml
                )

                root = ET.fromstring(
                    xml_text
                )

                record_id = get_record_id(
                    root
                )

                if record_id in processed_record_ids:
                    continue

                new_events.append(
                    (
                        record_id,
                        xml_text
                    )
                )

            except Exception as error:
                print(
                    f"[이벤트 읽기 실패] "
                    f"{error}"
                )

    new_events.sort(
        key=lambda item: item[0]
    )

    return new_events


# ============================================================
# Main
# ============================================================

def main():
    print(
        "=" * 70
    )

    print(
        "Windows Security XML Event Collector"
    )

    print(
        "=" * 70
    )

    print(
        "감시 이벤트: "
        "4624 / 4625 / 4663 / 4688"
    )

    print(
        f"4663 감시 폴더: "
        f"{MONITORED_FOLDER}"
    )

    print(
        f"FastAPI: "
        f"{API_URL}"
    )

    print(
        f"감시 주기: "
        f"{POLL_INTERVAL}초"
    )

    print(
        "4688 수집 정책: "
        "업무 패턴 + 보안 분석 프로세스 선택 수집"
    )

    print(
        f"4688 재전송 제한: "
        f"사용자/프로세스별 {PROCESS_COOLDOWN_SECONDS}초"
    )

    print(
        "=" * 70
    )

    try:
        last_record_id = (
            get_current_last_record_id()
        )

    except Exception as error:
        print()
        print(
            "Security 이벤트 로그를 "
            "읽을 수 없습니다."
        )

        print(
            error
        )

        print()

        print(
            "PyCharm을 관리자 권한으로 "
            "실행했는지 확인하세요."
        )

        return

    # Collector가 시작된 시점의 Record ID
    startup_record_id = last_record_id

    # 중복 처리를 막기 위한 Record ID 집합
    processed_record_ids = set()

    print()

    print(
        "Collector 초기화 완료"
    )

    print(
        f"현재 마지막 대상 Record ID: "
        f"{last_record_id}"
    )

    print()

    print(
        "4624 / 4625 / 중요 4663은 "
        "화면에 표시합니다."
    )

    print(
        "일반 4688은 수집하지 않습니다. "
        "업무 패턴 학습 및 보안 분석 대상만 SIEM에 전송합니다."
    )

    print(
        "수집 대상 4688은 화면에도 표시합니다."
    )

    print(
        "종료하려면 Ctrl+C"
    )

    try:
        while True:
            try:
                new_events = read_events_after(
                    last_record_id,
                    processed_record_ids
                )

                for (
                    record_id,
                    xml_text
                ) in new_events:

                    # Collector 시작 전에 이미 존재하던
                    # 이벤트는 SIEM에 다시 보내지 않는다.
                    if record_id <= startup_record_id:
                        processed_record_ids.add(
                            record_id
                        )

                        continue

                    # 이미 처리한 이벤트는 제외
                    if record_id in processed_record_ids:
                        continue

                    (
                        event_id,
                        _,
                        payload
                    ) = parse_event_xml(
                        xml_text
                    )

                    if payload is not None:
                        # 동일 사용자 + 동일 4688 프로세스는
                        # 60초 이내에 다시 전송하지 않는다.
                        if (
                            event_id == 4688
                            and is_process_in_cooldown(payload)
                        ):
                            processed_record_ids.add(
                                record_id
                            )

                            if record_id > last_record_id:
                                last_record_id = record_id

                            continue

                        show_output = (
                            should_print_event(
                                event_id,
                                payload
                            )
                        )

                        if show_output:
                            print_detected_event(
                                event_id,
                                record_id,
                                payload
                            )

                        # parse_4688을 통과한 업무 패턴/보안 분석 대상 4688만 전송한다.
                        send_event(
                            payload,
                            show_output=show_output
                        )

                    processed_record_ids.add(
                        record_id
                    )

                    if record_id > last_record_id:
                        last_record_id = record_id

                # processed_record_ids가 계속 커지는 것을 방지
                minimum_record_id = max(
                    0,
                    last_record_id - 1000
                )

                processed_record_ids = {
                    record_id
                    for record_id
                    in processed_record_ids
                    if record_id >= minimum_record_id
                }

            except Exception as error:
                print(
                    f"[수집 오류] "
                    f"{error}"
                )

            time.sleep(
                POLL_INTERVAL
            )

    except KeyboardInterrupt:
        print()
        print()

        print(
            "Collector를 종료합니다."
        )


if __name__ == "__main__":
    main()
