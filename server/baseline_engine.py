from collections import Counter
from datetime import datetime, timedelta

from server.models import SecurityEvent, MonitoredUser
from server.change_verification_engine import is_event_allowed_for_baseline


BASELINE_DAYS = 30

MIN_BASELINE_EVENTS = 20
MEDIUM_BASELINE_EVENTS = 50
HIGH_BASELINE_EVENTS = 100

# Adaptive UEBA Learning Guard
# 정상으로 판단된 LOW 이벤트만 개인 행동 기준선 학습에 사용
LEARNING_RISK_LEVEL = "LOW"


# Peer Group UEBA
# 같은 부서 + 같은 역할의 활성 모니터링 사용자를 우선 Peer로 사용한다.
# 본인은 Peer Group에서 제외한다.
MIN_PEER_USERS = 2
MIN_PEER_EVENTS = 20
PEER_GROUP_MAX_SCORE = 100


def _circular_hour_difference(hour1, hour2):
    difference = abs(hour1 - hour2)
    return min(difference, 24 - difference)


def _get_confidence(event_count):
    if event_count < MIN_BASELINE_EVENTS:
        return "LEARNING", 0.25

    if event_count < MEDIUM_BASELINE_EVENTS:
        return "LOW", 0.50

    if event_count < HIGH_BASELINE_EVENTS:
        return "MEDIUM", 0.75

    return "HIGH", 1.0


def _get_learning_events(
    db,
    user,
    since,
    reference_time
):
    """
    Adaptive UEBA Learning Guard

    개인 행동 기준선에는 LOW 위험도로
    최종 판정된 이벤트만 사용한다.

    MEDIUM / HIGH / CRITICAL 이벤트는
    보안 이벤트 기록에는 남아 있지만
    개인 정상 행동 학습에서는 제외된다.
    """

    learning_since = since

    monitored_user = (
        db.query(MonitoredUser)
        .filter(MonitoredUser.username == user)
        .first()
    )

    # 실제 모니터링 대상으로 등록된 사용자는
    # 등록 시점 이후의 행동만 개인 기준선 학습에 사용한다.
    #
    # office_demo / flex_demo처럼 MonitoredUser에 등록되지 않은
    # Adaptive UEBA 시연 사용자는 기존 30일 기준을 그대로 사용한다.
    if (
        monitored_user is not None
        and monitored_user.created_at is not None
        and monitored_user.created_at > learning_since
    ):
        learning_since = monitored_user.created_at

    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == user,
            SecurityEvent.timestamp >= learning_since,
            SecurityEvent.timestamp < reference_time,
            SecurityEvent.risk_level == LEARNING_RISK_LEVEL
        )
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    return [
        event
        for event in events
        if is_event_allowed_for_baseline(db, event)
    ]


def _get_active_hours(events):
    hour_counter = Counter()

    for event in events:
        if event.timestamp:
            hour_counter[event.timestamp.hour] += 1

    if not hour_counter:
        return []

    maximum_count = max(hour_counter.values())

    threshold = max(
        2,
        int(maximum_count * 0.30)
    )

    active_hours = [
        hour
        for hour, count in hour_counter.items()
        if count >= threshold
    ]

    return sorted(active_hours)


def _get_active_weekdays(events):
    weekday_counter = Counter()

    for event in events:
        if event.timestamp:
            weekday_counter[event.timestamp.weekday()] += 1

    if not weekday_counter:
        return []

    maximum_count = max(weekday_counter.values())

    threshold = max(
        2,
        int(maximum_count * 0.25)
    )

    active_weekdays = [
        weekday
        for weekday, count in weekday_counter.items()
        if count >= threshold
    ]

    return sorted(active_weekdays)


def _get_known_ips(events):
    ip_counter = Counter()

    for event in events:
        if event.source_ip:
            ip_counter[event.source_ip] += 1

    return {
        ip
        for ip, count in ip_counter.items()
        if count >= 2
    }


def _get_normal_processes(events):
    process_counter = Counter()

    for event in events:
        if (
            event.event_type == "process_execution"
            and event.process_name
        ):
            process_name = event.process_name.lower()
            process_counter[process_name] += 1

    return {
        process
        for process, count in process_counter.items()
        if count >= 2
    }


def _get_average_file_access(events):
    file_counts = [
        event.file_access_count
        for event in events
        if (
            event.event_type == "file_access"
            and event.file_access_count is not None
            and event.file_access_count > 0
        )
    ]

    if not file_counts:
        return 0

    return sum(file_counts) / len(file_counts)


def _get_usb_usage_rate(events):
    if not events:
        return 0

    usb_events = [
        event
        for event in events
        if (
            event.event_type == "usb_connected"
            or event.usb_connected == 1
        )
    ]

    return len(usb_events) / len(events)


def analyze_user_baseline(
    db,
    user,
    current_ip,
    current_hour,
    current_file_access_count=0,
    current_process_name=None,
    current_usb_connected=0,
    current_timestamp=None
):
    if current_timestamp is None:
        current_timestamp = datetime.now()

    since = current_timestamp - timedelta(
        days=BASELINE_DAYS
    )

    # --------------------------------
    # Learning Guard
    #
    # 전체 과거 이벤트가 아니라
    # LOW 위험도로 판정된 정상 이벤트만
    # 개인 행동 기준선으로 사용한다.
    # --------------------------------

    previous_events = _get_learning_events(
        db=db,
        user=user,
        since=since,
        reference_time=current_timestamp
    )

    event_count = len(previous_events)

    if event_count == 0:
        return 0, [
            "사용자 행동 기준 데이터 부족"
        ]

    confidence_level, confidence_weight = (
        _get_confidence(event_count)
    )

    baseline_score = 0
    reasons = []

    # --------------------------------
    # 1. 평소 사용 IP 학습
    # --------------------------------

    known_ips = _get_known_ips(
        previous_events
    )

    if (
        current_ip
        and known_ips
        and current_ip not in known_ips
    ):
        baseline_score += 25

        reasons.append(
            f"개인 행동 기준선에서 벗어난 신규 IP 접근: {current_ip}"
        )

    # --------------------------------
    # 2. 개인별 활동 시간대 학습
    # --------------------------------

    active_hours = _get_active_hours(
        previous_events
    )

    if active_hours:
        minimum_hour_difference = min(
            _circular_hour_difference(
                current_hour,
                normal_hour
            )
            for normal_hour in active_hours
        )

        if minimum_hour_difference >= 4:
            baseline_score += 20

            reasons.append(
                "개인별 평소 활동 시간대에서 크게 벗어난 접근"
            )

        elif minimum_hour_difference >= 2:
            baseline_score += 10

            reasons.append(
                "개인별 평소 활동 시간대와 다른 접근"
            )

    # --------------------------------
    # 3. 개인별 활동 요일 학습
    # --------------------------------

    active_weekdays = _get_active_weekdays(
        previous_events
    )

    current_weekday = (
        current_timestamp.weekday()
    )

    if (
        active_weekdays
        and current_weekday not in active_weekdays
    ):
        baseline_score += 10

        reasons.append(
            "평소 활동하지 않는 요일의 접근"
        )

    # --------------------------------
    # 4. 개인별 파일 접근량 학습
    # --------------------------------

    average_file_count = (
        _get_average_file_access(
            previous_events
        )
    )

    if (
        average_file_count > 0
        and current_file_access_count > 0
    ):
        if (
            current_file_access_count
            >= average_file_count * 5
            and current_file_access_count >= 10
        ):
            baseline_score += 25

            reasons.append(
                "개인 평균 대비 매우 높은 파일 접근량"
            )

        elif (
            current_file_access_count
            >= average_file_count * 3
            and current_file_access_count >= 10
        ):
            baseline_score += 15

            reasons.append(
                "개인 평균 대비 높은 파일 접근량"
            )

    # --------------------------------
    # 5. 개인별 프로세스 사용 습관 학습
    # --------------------------------

    normal_processes = _get_normal_processes(
        previous_events
    )

    if (
        current_process_name
        and normal_processes
    ):
        current_process = (
            current_process_name.lower()
        )

        if current_process not in normal_processes:
            baseline_score += 10

            reasons.append(
                f"평소 사용하지 않는 프로세스 실행: {current_process_name}"
            )

    # --------------------------------
    # 6. 개인별 USB 사용 습관 학습
    # --------------------------------

    usb_usage_rate = _get_usb_usage_rate(
        previous_events
    )

    if (
        current_usb_connected == 1
        and usb_usage_rate < 0.01
    ):
        baseline_score += 10

        reasons.append(
            "평소 USB 사용 빈도가 매우 낮은 사용자의 USB 연결"
        )

    # --------------------------------
    # 7. Baseline Confidence 반영
    # --------------------------------

    weighted_score = (
        baseline_score
        * confidence_weight
    )

    baseline_score = min(
        round(weighted_score, 2),
        100
    )

    if confidence_level == "LEARNING":
        reasons.append(
            f"개인 행동 기준선 학습 중 ({event_count}개 정상 이벤트)"
        )

    elif confidence_level == "LOW":
        reasons.append(
            f"개인 행동 기준선 신뢰도 낮음 ({event_count}개 정상 이벤트)"
        )

    elif confidence_level == "MEDIUM":
        reasons.append(
            f"개인 행동 기준선 신뢰도 보통 ({event_count}개 정상 이벤트)"
        )

    return baseline_score, reasons




def _get_peer_users(
    db,
    user
):
    """
    같은 department + role의 활성 모니터링 사용자를 Peer Group으로 구성한다.
    자기 자신은 제외한다.

    Peer가 충분하지 않으면 점수를 만들지 않는다.
    """
    target_user = (
        db.query(MonitoredUser)
        .filter(MonitoredUser.username == user)
        .first()
    )

    if target_user is None:
        return []

    if not target_user.department or not target_user.role:
        return []

    peer_rows = (
        db.query(MonitoredUser)
        .filter(
            MonitoredUser.username != user,
            MonitoredUser.department == target_user.department,
            MonitoredUser.role == target_user.role,
            MonitoredUser.monitoring_enabled == 1
        )
        .all()
    )

    return peer_rows


def _get_peer_learning_events(
    db,
    peer_users,
    since,
    reference_time
):
    """
    Peer Group도 Learning Guard를 동일하게 적용한다.

    각 Peer는 관리자 등록 시점 이후의 LOW 이벤트만 사용한다.
    따라서 과거 공격 이벤트나 등록 이전 로그가 Peer 정상 기준선을
    오염시키지 않는다.
    """
    events = []

    for peer in peer_users:
        peer_events = _get_learning_events(
            db=db,
            user=peer.username,
            since=since,
            reference_time=reference_time
        )

        events.extend(peer_events)

    events.sort(
        key=lambda event: (
            event.timestamp or datetime.min,
            event.id or 0
        )
    )

    return events


def analyze_peer_group_baseline(
    db,
    user,
    current_ip,
    current_hour,
    current_file_access_count=0,
    current_process_name=None,
    current_usb_connected=0,
    current_timestamp=None
):
    """
    Peer Group UEBA

    개인의 과거 행동이 아니라 같은 부서 + 같은 역할의 동료들이
    보이는 LOW 정상 행동 패턴과 현재 행동을 비교한다.

    개인 기준선이 부족한 LEARNING 단계에서 특히 보조 신호로
    사용할 수 있도록 설계한다.
    """
    if current_timestamp is None:
        current_timestamp = datetime.now()

    since = current_timestamp - timedelta(
        days=BASELINE_DAYS
    )

    peer_users = _get_peer_users(
        db=db,
        user=user
    )

    peer_usernames = [
        peer.username
        for peer in peer_users
    ]

    result = {
        "score": 0.0,
        "reasons": [],
        "applied": False,
        "group_available": False,
        "peer_user_count": len(peer_users),
        "peer_event_count": 0,
        "peer_users": peer_usernames,
        "group_key": None
    }

    target_user = (
        db.query(MonitoredUser)
        .filter(MonitoredUser.username == user)
        .first()
    )

    if target_user is not None:
        result["group_key"] = (
            f"{target_user.department or '-'} / "
            f"{target_user.role or '-'}"
        )

    # 한 명의 행동을 조직 표준처럼 취급하지 않기 위한 최소 조건
    if len(peer_users) < MIN_PEER_USERS:
        result["reasons"].append(
            f"Peer Group 학습 사용자 부족 "
            f"({len(peer_users)}/{MIN_PEER_USERS}명)"
        )
        return result

    peer_events = _get_peer_learning_events(
        db=db,
        peer_users=peer_users,
        since=since,
        reference_time=current_timestamp
    )

    peer_event_count = len(peer_events)
    result["peer_event_count"] = peer_event_count

    if peer_event_count < MIN_PEER_EVENTS:
        result["reasons"].append(
            f"Peer Group 정상 이벤트 부족 "
            f"({peer_event_count}/{MIN_PEER_EVENTS}개)"
        )
        return result

    result["group_available"] = True

    peer_score = 0
    peer_reasons = []

    # 1. Peer Group 활동 시간대
    active_hours = _get_active_hours(
        peer_events
    )

    if active_hours:
        minimum_hour_difference = min(
            _circular_hour_difference(
                current_hour,
                normal_hour
            )
            for normal_hour in active_hours
        )

        if minimum_hour_difference >= 4:
            peer_score += 20
            peer_reasons.append(
                "동일 직무 Peer Group의 평소 활동 시간대에서 크게 벗어난 접근"
            )

        elif minimum_hour_difference >= 2:
            peer_score += 10
            peer_reasons.append(
                "동일 직무 Peer Group의 평소 활동 시간대와 다른 접근"
            )

    # 2. Peer Group 활동 요일
    active_weekdays = _get_active_weekdays(
        peer_events
    )

    current_weekday = current_timestamp.weekday()

    if (
        active_weekdays
        and current_weekday not in active_weekdays
    ):
        peer_score += 10
        peer_reasons.append(
            "동일 직무 Peer Group이 평소 활동하지 않는 요일의 접근"
        )

    # 3. Peer Group 파일 접근량
    average_file_count = _get_average_file_access(
        peer_events
    )

    if (
        average_file_count > 0
        and current_file_access_count > 0
    ):
        if (
            current_file_access_count
            >= average_file_count * 5
            and current_file_access_count >= 10
        ):
            peer_score += 25
            peer_reasons.append(
                "동일 직무 Peer Group 평균 대비 매우 높은 파일 접근량"
            )

        elif (
            current_file_access_count
            >= average_file_count * 3
            and current_file_access_count >= 10
        ):
            peer_score += 15
            peer_reasons.append(
                "동일 직무 Peer Group 평균 대비 높은 파일 접근량"
            )

    # 4. Peer Group 프로세스 사용 패턴
    normal_processes = _get_normal_processes(
        peer_events
    )

    if (
        current_process_name
        and normal_processes
    ):
        current_process = current_process_name.lower()

        if current_process not in normal_processes:
            peer_score += 10
            peer_reasons.append(
                "동일 직무 Peer Group에서 일반적이지 않은 "
                f"프로세스 실행: {current_process_name}"
            )

    # 5. Peer Group USB 사용 패턴
    usb_usage_rate = _get_usb_usage_rate(
        peer_events
    )

    if (
        current_usb_connected == 1
        and usb_usage_rate < 0.01
    ):
        peer_score += 10
        peer_reasons.append(
            "동일 직무 Peer Group의 USB 사용 빈도가 매우 낮은 환경에서 USB 연결"
        )

    peer_score = min(
        round(peer_score, 2),
        PEER_GROUP_MAX_SCORE
    )

    result["score"] = peer_score
    result["reasons"] = peer_reasons
    result["applied"] = True

    return result


def get_peer_group_profile(
    db,
    user,
    reference_time=None
):
    """
    대시보드/검증용 Peer Group 프로필.
    """
    if reference_time is None:
        reference_time = datetime.now()

    since = reference_time - timedelta(
        days=BASELINE_DAYS
    )

    peer_users = _get_peer_users(
        db=db,
        user=user
    )

    peer_events = _get_peer_learning_events(
        db=db,
        peer_users=peer_users,
        since=since,
        reference_time=reference_time
    )

    target_user = (
        db.query(MonitoredUser)
        .filter(MonitoredUser.username == user)
        .first()
    )

    group_key = None

    if target_user is not None:
        group_key = (
            f"{target_user.department or '-'} / "
            f"{target_user.role or '-'}"
        )

    available = (
        len(peer_users) >= MIN_PEER_USERS
        and len(peer_events) >= MIN_PEER_EVENTS
    )

    return {
        "user": user,
        "group_key": group_key,
        "available": available,
        "minimum_peer_users": MIN_PEER_USERS,
        "minimum_peer_events": MIN_PEER_EVENTS,
        "peer_user_count": len(peer_users),
        "peer_event_count": len(peer_events),
        "peer_users": [
            peer.username
            for peer in peer_users
        ],
        "active_hours": _get_active_hours(
            peer_events
        ),
        "active_weekdays": _get_active_weekdays(
            peer_events
        ),
        "known_ips": sorted(
            _get_known_ips(peer_events)
        ),
        "average_file_access": round(
            _get_average_file_access(peer_events),
            2
        ),
        "normal_processes": sorted(
            _get_normal_processes(peer_events)
        ),
        "usb_usage_rate_percent": round(
            _get_usb_usage_rate(peer_events) * 100,
            2
        )
    }



def calculate_adaptive_compensation(
    db,
    user,
    current_hour,
    current_process_name=None,
    current_timestamp=None,
    rule_reasons=None,
    baseline_score=0,
    sequence_score=0,
    event_type=None,
    file_grade=None,
    file_access_count=0,
    usb_connected=0,
    login_fail_count=0
):
    """
    충분히 학습된 개인 정상 패턴이 고정 Rule의 오탐 가능성을
    뒷받침하는 경우에만 최종 위험도를 제한적으로 보정한다.

    안전 원칙:
    - LEARNING / LOW confidence에서는 보정하지 않는다.
    - 개인 기준선 자체가 이탈한 경우에는 보정하지 않는다.
    - 로그인 실패, 민감 문서, 대량 파일 접근, USB, 강한 Sequence가
      존재하면 보정하지 않는다.
    - 현재는 고정 시간 규칙의 "비정상 시간대 접근"만 보정한다.
      따라서 개인화가 명시적 보안 신호를 덮어쓰지 않는다.
    """

    if current_timestamp is None:
        current_timestamp = datetime.now()

    if rule_reasons is None:
        rule_reasons = []

    since = current_timestamp - timedelta(
        days=BASELINE_DAYS
    )

    previous_events = _get_learning_events(
        db=db,
        user=user,
        since=since,
        reference_time=current_timestamp
    )

    event_count = len(previous_events)

    confidence_level, confidence_weight = (
        _get_confidence(event_count)
    )

    result = {
        "score": 0.0,
        "reasons": [],
        "confidence_level": confidence_level,
        "confidence_weight": confidence_weight,
        "learning_event_count": event_count,
        "applied": False
    }

    # 충분한 정상 데이터가 쌓이기 전에는
    # 개인화 보정을 절대 적용하지 않는다.
    if confidence_level not in {
        "MEDIUM",
        "HIGH"
    }:
        return result

    # 개인 기준선에서 이미 이탈한 이벤트라면
    # 정상 패턴 보정을 적용하지 않는다.
    if baseline_score > 0:
        return result

    # 공격 시퀀스가 형성되고 있는 이벤트는
    # 개인화로 위험도를 낮추지 않는다.
    if sequence_score >= 20:
        return result

    # 명시적 위험 신호는 보정 금지
    if login_fail_count >= 3:
        return result

    if file_grade in {
        "내부",
        "대외비"
    }:
        return result

    if file_access_count >= 20:
        return result

    if usb_connected == 1:
        return result

    # 현재 Adaptive Compensation은
    # 전역 시간 규칙의 오탐만 안전하게 보정한다.
    if "비정상 시간대 접근" not in rule_reasons:
        return result

    active_hours = _get_active_hours(
        previous_events
    )

    if not active_hours:
        return result

    minimum_hour_difference = min(
        _circular_hour_difference(
            current_hour,
            normal_hour
        )
        for normal_hour in active_hours
    )

    # 개인 정상 시간대와 정확히 또는 인접 1시간 이내일 때만
    # 고정 시간 Rule을 개인 패턴으로 보정한다.
    if minimum_hour_difference > 1:
        return result

    # Rule Engine의 비정상 시간 점수는 +15이다.
    # MEDIUM confidence에서는 절반만,
    # HIGH confidence에서는 전부 보정한다.
    if confidence_level == "MEDIUM":
        compensation_score = 7.5
    else:
        compensation_score = 15.0

    result["score"] = compensation_score
    result["applied"] = True

    result["reasons"].append(
        (
            "Adaptive UEBA 정상 패턴 보정: "
            f"{current_hour:02d}시는 개인별 정상 활동 시간대와 일치 "
            f"({confidence_level} 신뢰도, -{compensation_score:g}점)"
        )
    )

    return result


def get_user_behavior_profile(
    db,
    user,
    reference_time=None
):
    if reference_time is None:
        reference_time = datetime.now()

    since = reference_time - timedelta(
        days=BASELINE_DAYS
    )

    # --------------------------------
    # Learning Guard 적용
    #
    # 사용자 행동 프로필 역시
    # LOW 정상 이벤트만 기반으로 생성한다.
    # --------------------------------

    events = _get_learning_events(
        db=db,
        user=user,
        since=since,
        reference_time=reference_time
    )

    event_count = len(events)

    confidence_level, confidence_weight = (
        _get_confidence(event_count)
    )

    known_ips = sorted(
        _get_known_ips(events)
    )

    active_hours = _get_active_hours(
        events
    )

    active_weekdays = _get_active_weekdays(
        events
    )

    normal_processes = sorted(
        _get_normal_processes(events)
    )

    average_file_access = round(
        _get_average_file_access(events),
        2
    )

    usb_usage_rate = round(
        _get_usb_usage_rate(events) * 100,
        2
    )

    return {
        "user": user,
        "learning_period_days": BASELINE_DAYS,

        # Learning Guard를 통과한 정상 이벤트 수
        "event_count": event_count,
        "learning_event_count": event_count,

        "confidence_level": confidence_level,
        "confidence_weight": confidence_weight,

        "learning_policy": "LOW_ONLY",

        "active_hours": active_hours,
        "active_weekdays": active_weekdays,
        "known_ips": known_ips,
        "average_file_access": average_file_access,
        "normal_processes": normal_processes,
        "usb_usage_rate_percent": usb_usage_rate
    }