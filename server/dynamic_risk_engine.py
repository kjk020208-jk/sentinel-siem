from collections import defaultdict
from datetime import datetime, timedelta
from math import exp

from server.models import SecurityEvent


# Dynamic User Risk Stage 3
#
# 핵심 정책
# 1. LOW 이벤트는 사용자 누적 위험도에 반영하지 않는다.
# 2. MEDIUM 이상만 위험 증거로 사용한다.
# 3. 같은 event_type이 짧은 시간에 반복되면 하나의 행동 군집으로 묶는다.
# 4. 군집에서는 가장 높은 risk_score 이벤트 하나만 대표값으로 사용한다.
# 5. 최근 행동일수록 높은 가중치, 오래된 행동은 시간 감쇠한다.
# 6. HIGH / CRITICAL은 MEDIUM보다 더 강하게 반영한다.
# 7. 같은 event_type 군집이 반복될수록 기여도를 체감시킨다.
#
# DB 스키마 변경 없음.
# 기존 Event Risk / Personal UEBA / Peer / Adaptive / Sequence 로직 변경 없음.

DYNAMIC_RISK_WINDOW_HOURS = 24
DYNAMIC_RISK_HALF_LIFE_HOURS = 6.0

# 동일 유형 이벤트가 이 시간 안에 반복되면 하나의 행동 군집으로 취급.
EVENT_CLUSTER_MINUTES = 10

MAX_DYNAMIC_RISK = 100.0

# 이벤트 등급별 사용자 위험 기여 배율.
LEVEL_MULTIPLIER = {
    "MEDIUM": 0.55,
    "HIGH": 0.85,
    "CRITICAL": 1.00,
}

# 같은 event_type 군집이 반복될 때 적용하는 체감 가중치.
# 최신 군집부터 1.0 -> 0.5 -> 0.25 -> 이후 0.1.
SAME_TYPE_DIMINISHING_WEIGHTS = (
    1.00,
    0.50,
    0.25,
)
SAME_TYPE_MIN_WEIGHT = 0.10


def _hours_between(newer_time, older_time):
    seconds = (
        newer_time - older_time
    ).total_seconds()

    return max(
        seconds / 3600.0,
        0.0
    )


def _time_decay_weight(event_time, reference_time):
    age_hours = _hours_between(
        reference_time,
        event_time
    )

    decay_constant = (
        0.6931471805599453
        / DYNAMIC_RISK_HALF_LIFE_HOURS
    )

    return exp(
        -decay_constant * age_hours
    )


def _get_recent_user_events(
    db,
    user,
    reference_time
):
    since = (
        reference_time
        - timedelta(
            hours=DYNAMIC_RISK_WINDOW_HOURS
        )
    )

    return (
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


def _is_risk_event(event):
    level = (
        event.risk_level or ""
    ).upper()

    return level in {
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }


def _cluster_risk_events(events):
    """
    같은 event_type이 10분 이내 반복되면 하나의 군집으로 묶는다.

    예:
    process_execution MEDIUM 100개가 몇 초 사이 발생
    -> 100개 독립 증거가 아니라 process_execution 군집 1개.

    군집 대표 이벤트는 가장 높은 risk_score를 사용하며,
    동점이면 가장 최근 이벤트를 사용한다.
    """
    by_type = defaultdict(list)

    for event in events:
        if not _is_risk_event(event):
            continue

        event_type = (
            event.event_type
            or "unknown"
        )

        by_type[event_type].append(event)

    clusters = []

    for event_type, typed_events in by_type.items():
        current_cluster = []

        for event in typed_events:
            if not current_cluster:
                current_cluster = [event]
                continue

            previous_event = current_cluster[-1]

            gap = (
                event.timestamp
                - previous_event.timestamp
            )

            if gap <= timedelta(
                minutes=EVENT_CLUSTER_MINUTES
            ):
                current_cluster.append(event)

            else:
                clusters.append(
                    _build_cluster(
                        event_type,
                        current_cluster
                    )
                )
                current_cluster = [event]

        if current_cluster:
            clusters.append(
                _build_cluster(
                    event_type,
                    current_cluster
                )
            )

    clusters.sort(
        key=lambda item: item["timestamp"],
        reverse=True
    )

    return clusters


def _build_cluster(event_type, events):
    representative = max(
        events,
        key=lambda event: (
            float(event.risk_score or 0),
            event.timestamp
        )
    )

    latest_event = max(
        events,
        key=lambda event: event.timestamp
    )

    return {
        "event_type": event_type,
        "events": events,
        "event_count": len(events),
        "representative": representative,
        # 시간 감쇠는 군집에서 가장 최근 활동 시점을 기준으로 한다.
        "timestamp": latest_event.timestamp,
    }


def _level_multiplier(level):
    return LEVEL_MULTIPLIER.get(
        (level or "").upper(),
        0.0
    )


def calculate_dynamic_user_risk(
    db,
    user,
    reference_time=None
):
    if reference_time is None:
        reference_time = datetime.now()

    events = _get_recent_user_events(
        db=db,
        user=user,
        reference_time=reference_time
    )

    risk_events = [
        event
        for event in events
        if _is_risk_event(event)
    ]

    clusters = _cluster_risk_events(
        risk_events
    )

    if not clusters:
        return {
            "user": user,
            "dynamic_risk_score": 0.0,
            "dynamic_risk_level": "LOW",
            "event_count": len(events),
            "risk_event_count": len(risk_events),
            "cluster_count": 0,
            "window_hours": DYNAMIC_RISK_WINDOW_HOURS,
            "half_life_hours": DYNAMIC_RISK_HALF_LIFE_HOURS,
            "cluster_minutes": EVENT_CLUSTER_MINUTES,
            "contributors": [],
            "reason": (
                "최근 24시간 내 MEDIUM 이상 "
                "사용자 위험 이벤트 없음"
            )
        }

    survival_probability = 1.0
    contributors = []
    type_occurrence_count = defaultdict(int)

    for cluster in clusters:
        representative = cluster[
            "representative"
        ]

        raw_score = float(
            representative.risk_score or 0
        )

        raw_score = max(
            min(raw_score, 100.0),
            0.0
        )

        level = (
            representative.risk_level
            or "MEDIUM"
        ).upper()

        level_multiplier = (
            _level_multiplier(level)
        )

        event_type = cluster[
            "event_type"
        ]

        occurrence_index = (
            type_occurrence_count[
                event_type
            ]
        )

        if occurrence_index < len(
            SAME_TYPE_DIMINISHING_WEIGHTS
        ):
            type_weight = (
                SAME_TYPE_DIMINISHING_WEIGHTS[
                    occurrence_index
                ]
            )
        else:
            type_weight = (
                SAME_TYPE_MIN_WEIGHT
            )

        type_occurrence_count[
            event_type
        ] += 1

        decay_weight = (
            _time_decay_weight(
                event_time=cluster[
                    "timestamp"
                ],
                reference_time=reference_time
            )
        )

        weighted_score = (
            raw_score
            * level_multiplier
            * decay_weight
            * type_weight
        )

        # 군집 대표 위험도가 감쇠 후 너무 작으면
        # 현재 사용자 위험 상태에는 반영하지 않는다.
        if weighted_score < 4:
            continue

        event_probability = min(
            weighted_score / 100.0,
            0.95
        )

        survival_probability *= (
            1.0 - event_probability
        )

        contributors.append({
            "event_id": representative.id,
            "event_type": cluster[
                "event_type"
            ],
            "timestamp": cluster[
                "timestamp"
            ],
            "cluster_event_count": cluster[
                "event_count"
            ],
            "risk_score": round(
                raw_score,
                2
            ),
            "risk_level": level,
            "level_multiplier": round(
                level_multiplier,
                2
            ),
            "same_type_occurrence": (
                occurrence_index + 1
            ),
            "type_weight": round(
                type_weight,
                2
            ),
            "decay_weight": round(
                decay_weight,
                4
            ),
            "weighted_score": round(
                weighted_score,
                2
            )
        })

    dynamic_score = (
        1.0 - survival_probability
    ) * 100.0

    dynamic_score = round(
        min(
            max(dynamic_score, 0.0),
            MAX_DYNAMIC_RISK
        ),
        2
    )

    if dynamic_score >= 80:
        dynamic_level = "CRITICAL"

    elif dynamic_score >= 60:
        dynamic_level = "HIGH"

    elif dynamic_score >= 30:
        dynamic_level = "MEDIUM"

    else:
        dynamic_level = "LOW"

    if contributors:
        reason = (
            f"최근 {DYNAMIC_RISK_WINDOW_HOURS}시간의 "
            f"MEDIUM 이상 위험 이벤트를 "
            f"{EVENT_CLUSTER_MINUTES}분 단위 행동 군집으로 묶고 "
            f"동일 행동 반복 체감 가중치와 시간 감쇠를 적용해 "
            f"{len(contributors)}개 증거를 누적"
        )

    else:
        reason = (
            "MEDIUM 이상 이벤트는 있으나 "
            "시간 감쇠 후 유의미한 위험 기여 없음"
        )

    return {
        "user": user,
        "dynamic_risk_score": dynamic_score,
        "dynamic_risk_level": dynamic_level,
        "event_count": len(events),
        "risk_event_count": len(
            risk_events
        ),
        "cluster_count": len(
            clusters
        ),
        "contributing_cluster_count": len(
            contributors
        ),
        "window_hours": DYNAMIC_RISK_WINDOW_HOURS,
        "half_life_hours": DYNAMIC_RISK_HALF_LIFE_HOURS,
        "cluster_minutes": EVENT_CLUSTER_MINUTES,
        "contributors": contributors,
        "reason": reason
    }


def get_dynamic_user_risk_profile(
    db,
    user,
    reference_time=None
):
    return calculate_dynamic_user_risk(
        db=db,
        user=user,
        reference_time=reference_time
    )
