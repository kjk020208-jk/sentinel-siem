from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import text

from server.database import SessionLocal
from server.models import SecurityEvent, MonitoredUser
from server.baseline_engine import get_user_behavior_profile


# ============================================================
# SENTINEL Exhibition Readiness Verification
# ============================================================
# Railway production DB를 변경하지 않고 읽기 전용으로 검증합니다.
#
# 확인 항목
# 1. 모니터링 사용자 15명
# 2. 전시용 가상 사용자 14명 + siem_demo
# 3. 전체 이벤트 30,000건 이상
# 4. 사용자별 이벤트 분포
# 5. 프로세스 다양성
# 6. 직군별 대표 프로세스 존재
# 7. Adaptive Personal UEBA Baseline 상태
# 8. Behavior Change 상태
# 9. siem_demo 보존
# 10. 전시 시작 전 HIGH / CRITICAL 상태
#
# 이 스크립트는 DB를 수정하지 않습니다.
# ============================================================


EXPECTED_USERS = [
    "dev01",
    "dev02",
    "dev03",
    "dev04",
    "office01",
    "office02",
    "finance01",
    "finance02",
    "sales01",
    "design01",
    "plan01",
    "admin01",
    "security01",
    "manager01",
    "siem_demo",
]

SYNTHETIC_USERS = [
    user
    for user in EXPECTED_USERS
    if user != "siem_demo"
]

EXPECTED_MIN_USERS = 15
EXPECTED_MIN_EVENTS = 30_000
EXPECTED_MIN_PROCESSES = 30

# 30K 전시 데이터에서 사용자별 최소 기대치.
# siem_demo는 실제 시연 사용자이므로 제외.
EXPECTED_MIN_EVENTS_PER_SYNTHETIC_USER = 1_500

# Baseline은 최근 30일 LOW 이벤트 기준.
EXPECTED_MIN_BASELINE_EVENTS = 100

ROLE_PROCESS_EXPECTATIONS = {
    "dev03": {
        "python.exe",
        "pycharm64.exe",
        "WindowsTerminal.exe",
    },
    "office01": {
        "EXCEL.EXE",
        "WINWORD.EXE",
        "OUTLOOK.EXE",
    },
    "admin01": {
        "powershell.exe",
        "WindowsTerminal.exe",
        "mmc.exe",
    },
    "security01": {
        "powershell.exe",
        "Wireshark.exe",
        "eventvwr.exe",
    },
}


PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str):
    results.append((status, name, detail))

    icon = {
        PASS: "[PASS]",
        WARN: "[WARN]",
        FAIL: "[FAIL]",
    }[status]

    print(
        f"{icon:<7} {name:<30} {detail}"
    )


def table_exists(db, name: str) -> bool:
    return (
        db.execute(
            text(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type='table'
                  AND name=:name
                """
            ),
            {"name": name},
        ).first()
        is not None
    )


def count_events_for_user(db, username: str) -> int:
    return int(
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user == username
        )
        .count()
    )


def distinct_processes_for_user(
    db,
    username: str,
) -> set[str]:
    rows = (
        db.query(SecurityEvent.process_name)
        .filter(
            SecurityEvent.user == username,
            SecurityEvent.process_name.isnot(None),
            SecurityEvent.process_name != "",
        )
        .distinct()
        .all()
    )

    return {
        str(row[0])
        for row in rows
        if row[0]
    }


def behavior_change_counts(db) -> dict[str, int]:
    if not table_exists(
        db,
        "behavior_change_observations",
    ):
        return {}

    rows = db.execute(
        text(
            """
            SELECT
                UPPER(COALESCE(status, 'UNKNOWN')) AS status,
                COUNT(*) AS cnt
            FROM behavior_change_observations
            GROUP BY UPPER(COALESCE(status, 'UNKNOWN'))
            """
        )
    ).mappings().all()

    return {
        str(row["status"]): int(row["cnt"])
        for row in rows
    }


def behavior_change_counts_by_user(
    db,
) -> dict[str, dict[str, int]]:
    if not table_exists(
        db,
        "behavior_change_observations",
    ):
        return {}

    rows = db.execute(
        text(
            """
            SELECT
                user,
                UPPER(COALESCE(status, 'UNKNOWN')) AS status,
                COUNT(*) AS cnt
            FROM behavior_change_observations
            GROUP BY
                user,
                UPPER(COALESCE(status, 'UNKNOWN'))
            """
        )
    ).mappings().all()

    output: dict[str, dict[str, int]] = {}

    for row in rows:
        username = str(
            row["user"] or "-"
        )

        output.setdefault(
            username,
            {},
        )[str(row["status"])] = int(
            row["cnt"]
        )

    return output


def get_active_monitored_users(db):
    return (
        db.query(MonitoredUser)
        .filter(
            MonitoredUser.monitoring_enabled == 1
        )
        .order_by(
            MonitoredUser.username.asc()
        )
        .all()
    )


def print_header(title: str):
    print()
    print("=" * 86)
    print(title)
    print("=" * 86)


def main():
    db = SessionLocal()

    try:
        print_header(
            "SENTINEL EXHIBITION READINESS CHECK"
        )

        print(
            f"검사 시각: {datetime.now():%Y-%m-%d %H:%M:%S}"
        )

        print(
            "DB를 수정하지 않는 읽기 전용 검사입니다."
        )

        # ====================================================
        # 1. Monitored users
        # ====================================================

        print_header(
            "[1] 모니터링 사용자"
        )

        active_users = (
            get_active_monitored_users(db)
        )

        active_names = {
            str(user.username)
            for user in active_users
        }

        if len(active_users) >= EXPECTED_MIN_USERS:
            record(
                PASS,
                "활성 모니터링 사용자",
                f"{len(active_users)}명",
            )
        else:
            record(
                FAIL,
                "활성 모니터링 사용자",
                f"{len(active_users)}명 / 기대 {EXPECTED_MIN_USERS}명 이상",
            )

        missing_users = [
            user
            for user in EXPECTED_USERS
            if user not in active_names
        ]

        if not missing_users:
            record(
                PASS,
                "전시 사용자 구성",
                "가상 14명 + siem_demo 모두 존재",
            )
        else:
            record(
                FAIL,
                "전시 사용자 구성",
                "누락: "
                + ", ".join(
                    missing_users
                ),
            )

        # ====================================================
        # 2. Event volume
        # ====================================================

        print_header(
            "[2] 이벤트 데이터 규모"
        )

        event_total = int(
            db.query(SecurityEvent).count()
        )

        if event_total >= EXPECTED_MIN_EVENTS:
            record(
                PASS,
                "전체 SecurityEvent",
                f"{event_total:,}건",
            )
        else:
            record(
                FAIL,
                "전체 SecurityEvent",
                f"{event_total:,}건 / 기대 {EXPECTED_MIN_EVENTS:,}건 이상",
            )

        synthetic_total = int(
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user.in_(
                    SYNTHETIC_USERS
                )
            )
            .count()
        )

        record(
            PASS
            if synthetic_total >= 30_000
            else WARN,
            "전시 가상 이벤트",
            f"{synthetic_total:,}건",
        )

        # ====================================================
        # 3. User event distribution
        # ====================================================

        print_header(
            "[3] 사용자별 이벤트 분포"
        )

        per_user_counts = {}

        for username in EXPECTED_USERS:
            count = count_events_for_user(
                db,
                username,
            )

            per_user_counts[
                username
            ] = count

            if username == "siem_demo":
                status = (
                    PASS
                    if count > 0
                    else WARN
                )

                record(
                    status,
                    f"{username} 이벤트",
                    f"{count:,}건 · 실제 시연 계정",
                )

                continue

            if (
                count
                >= EXPECTED_MIN_EVENTS_PER_SYNTHETIC_USER
            ):
                status = PASS
            else:
                status = FAIL

            record(
                status,
                f"{username} 이벤트",
                f"{count:,}건",
            )

        # ====================================================
        # 4. Process diversity
        # ====================================================

        print_header(
            "[4] 프로그램 / 프로세스 다양성"
        )

        all_processes = (
            db.query(
                SecurityEvent.process_name
            )
            .filter(
                SecurityEvent.user.in_(
                    SYNTHETIC_USERS
                ),
                SecurityEvent.process_name.isnot(
                    None
                ),
                SecurityEvent.process_name
                != "",
            )
            .distinct()
            .all()
        )

        process_names = {
            str(row[0])
            for row in all_processes
            if row[0]
        }

        if (
            len(process_names)
            >= EXPECTED_MIN_PROCESSES
        ):
            record(
                PASS,
                "고유 프로그램",
                f"{len(process_names)}종",
            )
        else:
            record(
                FAIL,
                "고유 프로그램",
                f"{len(process_names)}종 / 기대 {EXPECTED_MIN_PROCESSES}종 이상",
            )

        for (
            username,
            expected,
        ) in ROLE_PROCESS_EXPECTATIONS.items():
            actual = distinct_processes_for_user(
                db,
                username,
            )

            present = sorted(
                expected & actual
            )

            missing = sorted(
                expected - actual
            )

            if not missing:
                record(
                    PASS,
                    f"{username} 직군 프로세스",
                    ", ".join(
                        present
                    ),
                )
            else:
                record(
                    WARN,
                    f"{username} 직군 프로세스",
                    "누락: "
                    + ", ".join(
                        missing
                    ),
                )

        # ====================================================
        # 5. Baseline
        # ====================================================

        print_header(
            "[5] Adaptive Personal UEBA Baseline"
        )

        baseline_good = 0

        # 전체 14명을 검사하되,
        # 전시 출력이 너무 길지 않도록 핵심만 한 줄씩.
        for username in SYNTHETIC_USERS:
            try:
                profile = (
                    get_user_behavior_profile(
                        db=db,
                        user=username,
                    )
                )

                count = int(
                    profile.get(
                        "event_count",
                        0,
                    )
                    or 0
                )

                confidence = str(
                    profile.get(
                        "confidence_level",
                        profile.get(
                            "learning_status",
                            "UNKNOWN",
                        ),
                    )
                ).upper()

                active_hours = (
                    profile.get(
                        "active_hours",
                        [],
                    )
                    or []
                )

                if (
                    count
                    >= EXPECTED_MIN_BASELINE_EVENTS
                    and confidence == "HIGH"
                ):
                    status = PASS
                    baseline_good += 1
                elif count >= 50:
                    status = WARN
                else:
                    status = FAIL

                record(
                    status,
                    f"{username} Baseline",
                    f"{confidence} · LOW 학습 {count:,}건 · 시간 {active_hours}",
                )

            except Exception as exc:
                record(
                    FAIL,
                    f"{username} Baseline",
                    f"{type(exc).__name__}: {exc}",
                )

        if baseline_good == len(
            SYNTHETIC_USERS
        ):
            record(
                PASS,
                "Baseline 전체 상태",
                f"{baseline_good}/{len(SYNTHETIC_USERS)} HIGH",
            )
        else:
            record(
                WARN,
                "Baseline 전체 상태",
                f"HIGH {baseline_good}/{len(SYNTHETIC_USERS)}명",
            )

        # ====================================================
        # 6. Behavior Change
        # ====================================================

        print_header(
            "[6] Behavior Change Verification"
        )

        bc_counts = behavior_change_counts(
            db
        )

        if not bc_counts:
            record(
                FAIL,
                "Behavior Change 테이블",
                "데이터 없음",
            )
        else:
            observing = bc_counts.get(
                "OBSERVING",
                0,
            )
            accepted = bc_counts.get(
                "ACCEPTED",
                0,
            )
            rejected = bc_counts.get(
                "REJECTED",
                0,
            )

            record(
                PASS,
                "관찰 중",
                f"{observing:,}건",
            )

            if accepted > 0:
                record(
                    PASS,
                    "정상 승인",
                    f"{accepted:,}건",
                )
            else:
                record(
                    WARN,
                    "정상 승인",
                    "0건",
                )

            record(
                PASS,
                "학습 제외",
                f"{rejected:,}건",
            )

        bc_by_user = (
            behavior_change_counts_by_user(
                db
            )
        )

        missing_behavior_users = [
            username
            for username in SYNTHETIC_USERS
            if username not in bc_by_user
        ]

        if not missing_behavior_users:
            record(
                PASS,
                "가상 사용자 Behavior Change",
                "14명 모두 관찰 기록 존재",
            )
        else:
            record(
                WARN,
                "가상 사용자 Behavior Change",
                "기록 없음: "
                + ", ".join(
                    missing_behavior_users
                ),
            )

        # ====================================================
        # 7. Pre-exhibition risk state
        # ====================================================

        print_header(
            "[7] 전시 시작 전 위험 상태"
        )

        high_count = int(
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user.in_(
                    SYNTHETIC_USERS
                ),
                SecurityEvent.risk_level
                == "HIGH",
            )
            .count()
        )

        critical_count = int(
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user.in_(
                    SYNTHETIC_USERS
                ),
                SecurityEvent.risk_level
                == "CRITICAL",
            )
            .count()
        )

        medium_count = int(
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user.in_(
                    SYNTHETIC_USERS
                ),
                SecurityEvent.risk_level
                == "MEDIUM",
            )
            .count()
        )

        if high_count == 0:
            record(
                PASS,
                "가상 HIGH",
                "0건",
            )
        else:
            record(
                WARN,
                "가상 HIGH",
                f"{high_count:,}건",
            )

        if critical_count == 0:
            record(
                PASS,
                "가상 CRITICAL",
                "0건",
            )
        else:
            record(
                WARN,
                "가상 CRITICAL",
                f"{critical_count:,}건",
            )

        if medium_count > 0:
            record(
                PASS,
                "가상 MEDIUM",
                f"{medium_count:,}건 · 과거 검토 이벤트 존재",
            )
        else:
            record(
                WARN,
                "가상 MEDIUM",
                "0건",
            )

        # ====================================================
        # 8. siem_demo
        # ====================================================

        print_header(
            "[8] siem_demo 시연 계정"
        )

        siem_user = (
            db.query(MonitoredUser)
            .filter(
                MonitoredUser.username
                == "siem_demo"
            )
            .first()
        )

        if siem_user:
            record(
                PASS,
                "siem_demo 등록",
                f"monitoring_enabled={bool(siem_user.monitoring_enabled)}",
            )
        else:
            record(
                FAIL,
                "siem_demo 등록",
                "MonitoredUser 없음",
            )

        siem_count = count_events_for_user(
            db,
            "siem_demo",
        )

        record(
            PASS if siem_count > 0 else WARN,
            "siem_demo 이벤트",
            f"{siem_count:,}건",
        )

        # ====================================================
        # 9. Time-pattern sanity check
        # ====================================================

        print_header(
            "[9] 직군별 시간 패턴 간단 검증"
        )

        for username in [
            "dev03",
            "office01",
            "admin01",
        ]:
            rows = (
                db.query(
                    SecurityEvent.timestamp
                )
                .filter(
                    SecurityEvent.user
                    == username,
                    SecurityEvent.timestamp
                    .isnot(None),
                )
                .all()
            )

            hours = [
                row[0].hour
                for row in rows
                if row[0]
            ]

            night = sum(
                1
                for hour in hours
                if hour >= 20
                or hour <= 2
            )

            ratio = (
                night / len(hours) * 100
                if hours
                else 0.0
            )

            if username == "office01":
                status = (
                    PASS
                    if ratio < 15
                    else WARN
                )
            else:
                status = (
                    PASS
                    if ratio > 5
                    else WARN
                )

            record(
                status,
                f"{username} 야간 활동",
                f"{night:,}/{len(hours):,}건 · {ratio:.1f}%",
            )

        # ====================================================
        # Final
        # ====================================================

        print_header(
            "FINAL RESULT"
        )

        pass_count = sum(
            1
            for status, _, _ in results
            if status == PASS
        )

        warn_count = sum(
            1
            for status, _, _ in results
            if status == WARN
        )

        fail_count = sum(
            1
            for status, _, _ in results
            if status == FAIL
        )

        print(
            f"PASS : {pass_count}"
        )

        print(
            f"WARN : {warn_count}"
        )

        print(
            f"FAIL : {fail_count}"
        )

        print()

        if fail_count == 0:
            print(
                "[READY] 치명적인 전시 준비 문제는 발견되지 않았습니다."
            )
        else:
            print(
                "[NOT READY] FAIL 항목을 전시 전에 수정해야 합니다."
            )

        print()
        print(
            "WARN은 반드시 오류라는 뜻은 아니며, "
            "전시 의도와 데이터 특성을 확인해야 하는 항목입니다."
        )

    finally:
        db.close()


if __name__ == "__main__":
    main()
