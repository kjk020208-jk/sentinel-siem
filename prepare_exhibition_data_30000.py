from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy import text

from server.database import SessionLocal
from server.main import EventCreate, process_security_event
from server.models import SecurityEvent, MonitoredUser


# ============================================================
# SENTINEL Exhibition Dataset v2
# ============================================================
# 목적
# - 작품전시회용 "운영 중인 조직"처럼 보이는 현실적인 데이터셋 구성
# - 기본값: 가상 사용자 14명 + 실제 시연 사용자 siem_demo = 총 15명
# - 기본값: 가상 이벤트 약 30,000건
# - 기간: 최근 90일
# - 직군별 정상 시간대 / 야간 / 주말 / 애플리케이션 / 파일 / USB 패턴 차등
# - 개발자/IT/보안 직군의 야간·주말 작업을 정상 패턴으로 학습
# - 일부 MEDIUM 이상행동만 생성하고 HIGH/CRITICAL은 사전 생성하지 않음
# - siem_demo의 실제 이벤트 / Behavior Change / Endpoint 학습은 보존
# - CERT 100K 데이터는 건드리지 않음
#
# 실행 위치:
#   C:\Users\김재경\PycharmProjects\siemueba
#
# 기본 실행:
#   python prepare_exhibition_data_30000.py
#
# 이벤트 수 조정:
#   python prepare_exhibition_data_30000.py --target-events 30000
#
# 실제 DB 변경 전 구성만 확인:
#   python prepare_exhibition_data_30000.py --dry-run
# ============================================================


RANDOM_SEED = 20261118
REAL_DEMO_USER = "siem_demo"
SOURCE_NAME = "exhibition_seed_v2"

DEFAULT_TARGET_EVENTS = 30_000
DEFAULT_HISTORY_DAYS = 90

# 사용자마다 실제 파이프라인을 통과시켜 학습시키는 정상 이벤트 수.
# 전체 30,000건을 모두 분석 파이프라인으로 돌리면 느리므로,
# 반복 정상 행동은 실제 엔진으로 학습시키고 나머지는 과거 이력으로 대량 입력한다.
LEARNING_EVENTS_PER_USER = 72

# 전시 화면에 보일 MEDIUM 수준 검토 이벤트 비율.
# 30,000건 기준 약 240건(0.8%).
MEDIUM_ANOMALY_RATIO = 0.008

random.seed(RANDOM_SEED)


@dataclass(frozen=True)
class UserProfile:
    username: str
    display_name: str
    department: str
    role: str
    category: str

    host: str
    ip: str

    # (process_name, weight)
    processes: tuple[tuple[str, int], ...]
    files: tuple[str, ...]

    # 평일 정상 근무 시간
    weekday_start: int
    weekday_end: int

    # 근무시간 이후 정상 작업 확률
    evening_probability: float
    evening_end: int

    # 주말 정상 작업 확률
    weekend_probability: float

    # 정상 업무에서 USB 발생 확률
    usb_probability: float

    # 전체 이벤트 분배 가중치
    volume_weight: float

    # 이벤트 구성
    process_ratio: float
    file_ratio: float
    login_ratio: float


def P(*items):
    return tuple(items)


USERS: tuple[UserProfile, ...] = (

    # ========================================================
    # 개발 직군
    # ========================================================
    UserProfile(
        username="dev01",
        display_name="김도윤",
        department="플랫폼개발팀",
        role="Backend Developer",
        category="DEVELOPER",
        host="DEV-BE-01",
        ip="10.10.10.21",
        processes=P(
            ("pycharm64.exe", 18),
            ("python.exe", 17),
            ("chrome.exe", 13),
            ("WindowsTerminal.exe", 10),
            ("git.exe", 9),
            ("Code.exe", 8),
            ("docker.exe", 7),
            ("Postman.exe", 6),
            ("DBeaver.exe", 4),
            ("cmd.exe", 4),
            ("msedge.exe", 3),
            ("explorer.exe", 7),
            ("notepad.exe", 3),
        ),
        files=(
            "api_design.md",
            "requirements.txt",
            "backend_notes.txt",
            "database_schema.sql",
            "test_result.json",
            "deployment_checklist.xlsx",
            "docker-compose.yml",
            "application.yaml",
            "README.md",
        ),
        weekday_start=9,
        weekday_end=19,
        evening_probability=0.31,
        evening_end=24,
        weekend_probability=0.18,
        usb_probability=0.002,
        volume_weight=1.20,
        process_ratio=0.74,
        file_ratio=0.18,
        login_ratio=0.08,
    ),

    UserProfile(
        username="dev02",
        display_name="박서준",
        department="프론트엔드팀",
        role="Frontend Developer",
        category="DEVELOPER",
        host="DEV-FE-01",
        ip="10.10.10.22",
        processes=P(
            ("Code.exe", 20),
            ("chrome.exe", 18),
            ("node.exe", 14),
            ("npm.cmd", 11),
            ("WindowsTerminal.exe", 8),
            ("git.exe", 8),
            ("Figma.exe", 6),
            ("Postman.exe", 5),
            ("msedge.exe", 4),
            ("explorer.exe", 7),
            ("notepad.exe", 3),
        ),
        files=(
            "package.json",
            "App.jsx",
            "styles.css",
            "vite.config.js",
            "ui_spec.pdf",
            "frontend_notes.md",
            "release_checklist.xlsx",
            "design_tokens.json",
        ),
        weekday_start=9,
        weekday_end=20,
        evening_probability=0.35,
        evening_end=24,
        weekend_probability=0.20,
        usb_probability=0.002,
        volume_weight=1.18,
        process_ratio=0.76,
        file_ratio=0.16,
        login_ratio=0.08,
    ),

    UserProfile(
        username="dev03",
        display_name="이현우",
        department="데이터개발팀",
        role="Data Engineer",
        category="DEVELOPER",
        host="DEV-DATA-01",
        ip="10.10.10.23",
        processes=P(
            ("pycharm64.exe", 15),
            ("python.exe", 18),
            ("chrome.exe", 11),
            ("WindowsTerminal.exe", 10),
            ("Code.exe", 8),
            ("git.exe", 8),
            ("DBeaver.exe", 8),
            ("java.exe", 6),
            ("docker.exe", 6),
            ("EXCEL.EXE", 4),
            ("PowerBI.exe", 4),
            ("explorer.exe", 6),
            ("notepad.exe", 3),
        ),
        files=(
            "etl_job.py",
            "pipeline_config.yaml",
            "dataset_sample.csv",
            "query.sql",
            "data_quality.xlsx",
            "model_notes.md",
            "warehouse_schema.sql",
            "spark_job.py",
        ),
        weekday_start=10,
        weekday_end=20,
        evening_probability=0.39,
        evening_end=1,
        weekend_probability=0.24,
        usb_probability=0.002,
        volume_weight=1.22,
        process_ratio=0.75,
        file_ratio=0.17,
        login_ratio=0.08,
    ),

    UserProfile(
        username="dev04",
        display_name="최민재",
        department="QA자동화팀",
        role="QA Engineer",
        category="DEVELOPER",
        host="QA-PC-01",
        ip="10.10.10.24",
        processes=P(
            ("chrome.exe", 15),
            ("Code.exe", 13),
            ("python.exe", 11),
            ("Postman.exe", 10),
            ("WindowsTerminal.exe", 9),
            ("git.exe", 7),
            ("msedge.exe", 7),
            ("EXCEL.EXE", 6),
            ("cmd.exe", 5),
            ("notepad.exe", 5),
            ("explorer.exe", 8),
        ),
        files=(
            "test_case.xlsx",
            "api_test.json",
            "regression_result.xlsx",
            "bug_report.docx",
            "automation.py",
            "release_note.docx",
            "test_evidence.pdf",
        ),
        weekday_start=9,
        weekday_end=19,
        evening_probability=0.24,
        evening_end=23,
        weekend_probability=0.13,
        usb_probability=0.003,
        volume_weight=1.10,
        process_ratio=0.70,
        file_ratio=0.21,
        login_ratio=0.09,
    ),

    # ========================================================
    # 일반 사무 / 인사 / 경영지원
    # ========================================================
    UserProfile(
        username="office01",
        display_name="윤지민",
        department="인사팀",
        role="HR Specialist",
        category="OFFICE",
        host="HR-PC-01",
        ip="10.10.20.31",
        processes=P(
            ("EXCEL.EXE", 20),
            ("WINWORD.EXE", 18),
            ("OUTLOOK.EXE", 15),
            ("Teams.exe", 12),
            ("chrome.exe", 11),
            ("AcroRd32.exe", 8),
            ("POWERPNT.EXE", 5),
            ("OneDrive.exe", 5),
            ("explorer.exe", 6),
            ("calc.exe", 2),
        ),
        files=(
            "employee_schedule.xlsx",
            "leave_policy.docx",
            "recruiting_plan.xlsx",
            "training_material.pdf",
            "organization_chart.pptx",
            "hr_meeting_notes.docx",
            "attendance_report.xlsx",
        ),
        weekday_start=8,
        weekday_end=18,
        evening_probability=0.04,
        evening_end=20,
        weekend_probability=0.006,
        usb_probability=0.004,
        volume_weight=0.90,
        process_ratio=0.58,
        file_ratio=0.32,
        login_ratio=0.10,
    ),

    UserProfile(
        username="office02",
        display_name="정하린",
        department="경영지원팀",
        role="Office Administrator",
        category="OFFICE",
        host="ADM-OFFICE-01",
        ip="10.10.20.32",
        processes=P(
            ("OUTLOOK.EXE", 17),
            ("EXCEL.EXE", 16),
            ("WINWORD.EXE", 14),
            ("Teams.exe", 13),
            ("chrome.exe", 12),
            ("POWERPNT.EXE", 8),
            ("AcroRd32.exe", 7),
            ("OneDrive.exe", 6),
            ("calc.exe", 3),
            ("explorer.exe", 7),
        ),
        files=(
            "meeting_room.xlsx",
            "office_inventory.xlsx",
            "vendor_list.xlsx",
            "internal_notice.docx",
            "expense_form.xlsx",
            "meeting_minutes.docx",
            "purchase_request.xlsx",
        ),
        weekday_start=8,
        weekday_end=18,
        evening_probability=0.04,
        evening_end=20,
        weekend_probability=0.006,
        usb_probability=0.006,
        volume_weight=0.88,
        process_ratio=0.57,
        file_ratio=0.33,
        login_ratio=0.10,
    ),

    # ========================================================
    # 재무 / 회계
    # ========================================================
    UserProfile(
        username="finance01",
        display_name="한예진",
        department="재무팀",
        role="Financial Analyst",
        category="FINANCE",
        host="FIN-PC-01",
        ip="10.10.30.41",
        processes=P(
            ("EXCEL.EXE", 28),
            ("AcroRd32.exe", 15),
            ("OUTLOOK.EXE", 12),
            ("chrome.exe", 10),
            ("WINWORD.EXE", 9),
            ("Teams.exe", 8),
            ("POWERPNT.EXE", 5),
            ("OneDrive.exe", 5),
            ("calc.exe", 4),
            ("PowerBI.exe", 4),
            ("explorer.exe", 6),
        ),
        files=(
            "monthly_report.xlsx",
            "budget_plan.xlsx",
            "expense_summary.xlsx",
            "invoice_review.pdf",
            "cashflow_forecast.xlsx",
            "finance_meeting.pptx",
            "quarterly_forecast.xlsx",
            "payment_status.xlsx",
        ),
        weekday_start=8,
        weekday_end=19,
        evening_probability=0.08,
        evening_end=21,
        weekend_probability=0.015,
        usb_probability=0.001,
        volume_weight=0.98,
        process_ratio=0.55,
        file_ratio=0.36,
        login_ratio=0.09,
    ),

    UserProfile(
        username="finance02",
        display_name="송민서",
        department="회계팀",
        role="Accountant",
        category="FINANCE",
        host="FIN-PC-02",
        ip="10.10.30.42",
        processes=P(
            ("EXCEL.EXE", 30),
            ("AcroRd32.exe", 17),
            ("OUTLOOK.EXE", 12),
            ("chrome.exe", 8),
            ("WINWORD.EXE", 8),
            ("Teams.exe", 7),
            ("OneDrive.exe", 6),
            ("calc.exe", 5),
            ("explorer.exe", 7),
        ),
        files=(
            "ledger.xlsx",
            "tax_invoice.pdf",
            "accounting_close.xlsx",
            "payment_schedule.xlsx",
            "audit_request.docx",
            "receipt_summary.xlsx",
            "closing_checklist.xlsx",
        ),
        weekday_start=8,
        weekday_end=19,
        evening_probability=0.09,
        evening_end=21,
        weekend_probability=0.015,
        usb_probability=0.001,
        volume_weight=0.98,
        process_ratio=0.53,
        file_ratio=0.38,
        login_ratio=0.09,
    ),

    # ========================================================
    # 영업
    # ========================================================
    UserProfile(
        username="sales01",
        display_name="강태윤",
        department="영업1팀",
        role="Sales Manager",
        category="SALES",
        host="SALES-PC-01",
        ip="10.10.40.51",
        processes=P(
            ("OUTLOOK.EXE", 18),
            ("chrome.exe", 16),
            ("POWERPNT.EXE", 15),
            ("EXCEL.EXE", 13),
            ("Teams.exe", 12),
            ("WINWORD.EXE", 7),
            ("AcroRd32.exe", 6),
            ("OneDrive.exe", 5),
            ("msedge.exe", 3),
            ("explorer.exe", 5),
        ),
        files=(
            "sales_pipeline.xlsx",
            "customer_proposal.pptx",
            "quotation.xlsx",
            "weekly_sales.xlsx",
            "meeting_notes.docx",
            "product_catalog.pdf",
            "customer_schedule.xlsx",
        ),
        weekday_start=8,
        weekday_end=20,
        evening_probability=0.16,
        evening_end=22,
        weekend_probability=0.06,
        usb_probability=0.009,
        volume_weight=1.03,
        process_ratio=0.61,
        file_ratio=0.29,
        login_ratio=0.10,
    ),

    # ========================================================
    # 디자인 / 기획
    # ========================================================
    UserProfile(
        username="design01",
        display_name="오수빈",
        department="UX디자인팀",
        role="UX Designer",
        category="DESIGN",
        host="DESIGN-PC-01",
        ip="10.10.60.61",
        processes=P(
            ("Figma.exe", 23),
            ("Photoshop.exe", 15),
            ("Illustrator.exe", 11),
            ("chrome.exe", 13),
            ("Teams.exe", 9),
            ("POWERPNT.EXE", 8),
            ("Acrobat.exe", 6),
            ("OneDrive.exe", 5),
            ("explorer.exe", 7),
            ("notepad.exe", 3),
        ),
        files=(
            "wireframe.fig",
            "design_system.pdf",
            "prototype_review.pptx",
            "asset_list.xlsx",
            "ux_research.docx",
            "design_notes.txt",
            "component_guide.pdf",
        ),
        weekday_start=9,
        weekday_end=20,
        evening_probability=0.19,
        evening_end=23,
        weekend_probability=0.10,
        usb_probability=0.003,
        volume_weight=1.02,
        process_ratio=0.66,
        file_ratio=0.25,
        login_ratio=0.09,
    ),

    UserProfile(
        username="plan01",
        display_name="임채원",
        department="서비스기획팀",
        role="Product Planner",
        category="PLANNING",
        host="PLAN-PC-01",
        ip="10.10.60.62",
        processes=P(
            ("POWERPNT.EXE", 19),
            ("EXCEL.EXE", 15),
            ("WINWORD.EXE", 13),
            ("chrome.exe", 13),
            ("Teams.exe", 12),
            ("Figma.exe", 7),
            ("OUTLOOK.EXE", 7),
            ("AcroRd32.exe", 5),
            ("OneDrive.exe", 4),
            ("explorer.exe", 5),
        ),
        files=(
            "service_spec.pptx",
            "roadmap.xlsx",
            "requirement.docx",
            "market_research.pdf",
            "meeting_minutes.docx",
            "feature_priority.xlsx",
            "release_plan.pptx",
        ),
        weekday_start=9,
        weekday_end=20,
        evening_probability=0.15,
        evening_end=22,
        weekend_probability=0.06,
        usb_probability=0.002,
        volume_weight=0.98,
        process_ratio=0.59,
        file_ratio=0.31,
        login_ratio=0.10,
    ),

    # ========================================================
    # IT / 보안
    # ========================================================
    UserProfile(
        username="admin01",
        display_name="김성훈",
        department="IT운영팀",
        role="System Administrator",
        category="ADMIN",
        host="ADMIN-PC-01",
        ip="10.10.50.10",
        processes=P(
            ("powershell.exe", 18),
            ("WindowsTerminal.exe", 15),
            ("mmc.exe", 11),
            ("mstsc.exe", 10),
            ("cmd.exe", 9),
            ("eventvwr.exe", 8),
            ("taskmgr.exe", 7),
            ("WinSCP.exe", 5),
            ("putty.exe", 4),
            ("chrome.exe", 6),
            ("notepad.exe", 4),
            ("explorer.exe", 3),
        ),
        files=(
            "maintenance_log.txt",
            "asset_inventory.xlsx",
            "patch_schedule.xlsx",
            "server_checklist.docx",
            "network_change.docx",
            "incident_note.txt",
            "backup_report.xlsx",
            "change_request.docx",
        ),
        weekday_start=7,
        weekday_end=21,
        evening_probability=0.29,
        evening_end=24,
        weekend_probability=0.18,
        usb_probability=0.010,
        volume_weight=1.15,
        process_ratio=0.75,
        file_ratio=0.16,
        login_ratio=0.09,
    ),

    UserProfile(
        username="security01",
        display_name="문지후",
        department="정보보안팀",
        role="Security Analyst",
        category="SECURITY",
        host="SOC-PC-01",
        ip="10.10.50.11",
        processes=P(
            ("chrome.exe", 13),
            ("powershell.exe", 13),
            ("Wireshark.exe", 12),
            ("WindowsTerminal.exe", 11),
            ("eventvwr.exe", 10),
            ("mmc.exe", 8),
            ("cmd.exe", 7),
            ("mstsc.exe", 6),
            ("putty.exe", 5),
            ("WinSCP.exe", 4),
            ("EXCEL.EXE", 4),
            ("notepad.exe", 4),
            ("explorer.exe", 3),
        ),
        files=(
            "incident_report.docx",
            "ioc_list.xlsx",
            "security_review.pdf",
            "firewall_change.xlsx",
            "investigation_notes.txt",
            "vulnerability_result.xlsx",
            "threat_hunting.xlsx",
            "soc_handover.docx",
        ),
        weekday_start=7,
        weekday_end=22,
        evening_probability=0.33,
        evening_end=2,
        weekend_probability=0.22,
        usb_probability=0.006,
        volume_weight=1.17,
        process_ratio=0.76,
        file_ratio=0.15,
        login_ratio=0.09,
    ),

    # ========================================================
    # 관리자
    # ========================================================
    UserProfile(
        username="manager01",
        display_name="이준호",
        department="경영기획실",
        role="Department Manager",
        category="MANAGER",
        host="MGR-PC-01",
        ip="10.10.70.71",
        processes=P(
            ("OUTLOOK.EXE", 20),
            ("Teams.exe", 15),
            ("POWERPNT.EXE", 14),
            ("EXCEL.EXE", 13),
            ("WINWORD.EXE", 11),
            ("chrome.exe", 10),
            ("AcroRd32.exe", 7),
            ("OneDrive.exe", 5),
            ("explorer.exe", 5),
        ),
        files=(
            "management_report.pptx",
            "quarterly_kpi.xlsx",
            "strategy_plan.docx",
            "business_review.pdf",
            "team_budget.xlsx",
            "meeting_brief.docx",
            "executive_summary.pptx",
        ),
        weekday_start=8,
        weekday_end=21,
        evening_probability=0.12,
        evening_end=22,
        weekend_probability=0.03,
        usb_probability=0.003,
        volume_weight=0.90,
        process_ratio=0.56,
        file_ratio=0.34,
        login_ratio=0.10,
    ),
)


# ============================================================
# DB helpers
# ============================================================

def table_exists(db, name: str) -> bool:
    return db.execute(
        text(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type='table' AND name=:name
            """
        ),
        {"name": name},
    ).first() is not None


def table_columns(db, name: str) -> set[str]:
    if not table_exists(db, name):
        return set()

    return {
        row["name"]
        for row in db.execute(
            text(f"PRAGMA table_info({name})")
        ).mappings().all()
    }


def ids_for_user(db, table_name: str, username: str) -> list[int]:
    if not table_exists(db, table_name):
        return []

    columns = table_columns(db, table_name)

    if "id" not in columns or "user" not in columns:
        return []

    return [
        int(row[0])
        for row in db.execute(
            text(
                f"SELECT id FROM {table_name} "
                f"WHERE user=:user"
            ),
            {"user": username},
        ).all()
    ]


def delete_ids(
    db,
    table_name: str,
    column_name: str,
    ids: list[int],
) -> int:
    if not ids or not table_exists(db, table_name):
        return 0

    if column_name not in table_columns(db, table_name):
        return 0

    total = 0

    # SQLite 변수 개수 제한을 피하기 위해 500개 단위로 삭제.
    for offset in range(0, len(ids), 500):
        chunk = ids[offset:offset + 500]

        marks = ",".join(
            f":v{i}" for i in range(len(chunk))
        )

        params = {
            f"v{i}": value
            for i, value in enumerate(chunk)
        }

        result = db.execute(
            text(
                f"DELETE FROM {table_name} "
                f"WHERE {column_name} IN ({marks})"
            ),
            params,
        )

        total += int(result.rowcount or 0)

    return total


def delete_user_rows(db, table_name: str, username: str) -> int:
    if not table_exists(db, table_name):
        return 0

    if "user" not in table_columns(db, table_name):
        return 0

    result = db.execute(
        text(
            f"DELETE FROM {table_name} "
            f"WHERE user=:user"
        ),
        {"user": username},
    )

    return int(result.rowcount or 0)


def reset_synthetic_user(db, username: str) -> int:
    """
    전시용 가상 사용자 데이터만 초기화.
    siem_demo / CERT 데이터는 절대 대상에 포함하지 않는다.
    """

    event_ids = ids_for_user(
        db,
        "security_events",
        username,
    )

    incident_ids = ids_for_user(
        db,
        "security_incidents",
        username,
    )

    deleted = 0

    deleted += delete_ids(
        db,
        "event_risk_explanations",
        "event_id",
        event_ids,
    )

    deleted += delete_ids(
        db,
        "response_playbook_executions",
        "incident_id",
        incident_ids,
    )

    deleted += delete_user_rows(
        db,
        "event_context",
        username,
    )

    deleted += delete_user_rows(
        db,
        "behavior_change_observations",
        username,
    )

    deleted += delete_user_rows(
        db,
        "security_incidents",
        username,
    )

    deleted += delete_user_rows(
        db,
        "security_events",
        username,
    )

    return deleted


def ensure_monitored_user(db, profile: UserProfile) -> None:
    user = (
        db.query(MonitoredUser)
        .filter(MonitoredUser.username == profile.username)
        .first()
    )

    if user is None:
        user = MonitoredUser(
            username=profile.username,
            display_name=profile.display_name,
            department=profile.department,
            role=profile.role,
            monitoring_enabled=1,
        )

        db.add(user)

    else:
        user.display_name = profile.display_name
        user.department = profile.department
        user.role = profile.role
        user.monitoring_enabled = 1


def ensure_demo_user_enabled(db) -> None:
    user = (
        db.query(MonitoredUser)
        .filter(MonitoredUser.username == REAL_DEMO_USER)
        .first()
    )

    if user is not None:
        user.monitoring_enabled = 1


# ============================================================
# Realistic pattern generation
# ============================================================

def weighted_process(profile: UserProfile) -> str:
    return random.choices(
        [item[0] for item in profile.processes],
        weights=[item[1] for item in profile.processes],
        k=1,
    )[0]


def parent_process_for(process_name: str) -> str:
    p = process_name.lower()

    if p in {
        "python.exe",
        "node.exe",
        "npm.cmd",
        "git.exe",
        "docker.exe",
        "java.exe",
    }:
        return random.choice(
            [
                "WindowsTerminal.exe",
                "Code.exe",
                "pycharm64.exe",
                "cmd.exe",
            ]
        )

    if p in {
        "powershell.exe",
        "cmd.exe",
        "mmc.exe",
        "mstsc.exe",
        "eventvwr.exe",
        "winscp.exe",
        "putty.exe",
    }:
        return random.choice(
            [
                "explorer.exe",
                "WindowsTerminal.exe",
            ]
        )

    return "explorer.exe"


def date_range_start(history_days: int) -> datetime:
    now = datetime.now()

    return (
        now - timedelta(days=history_days)
    ).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )


def choose_work_timestamp(
    profile: UserProfile,
    start: datetime,
    end: datetime,
) -> datetime:
    """
    사용자 직군별 정상 시간대 패턴을 반영해 timestamp 생성.
    """

    for _ in range(1000):
        day_offset = random.randint(
            0,
            max(0, (end.date() - start.date()).days),
        )

        day = start + timedelta(days=day_offset)

        is_weekend = day.weekday() >= 5

        if is_weekend:
            if random.random() > profile.weekend_probability:
                continue

            hour = random.randint(
                10,
                min(
                    23,
                    max(
                        12,
                        profile.weekday_end,
                    ),
                ),
            )

        else:
            if random.random() < profile.evening_probability:
                evening_start = max(
                    profile.weekday_end,
                    18,
                )

                if profile.evening_end >= evening_start:
                    # datetime.hour는 0~23만 허용한다.
                    # 프로필에서 evening_end=24는 "자정 직전까지"라는 의미로
                    # 사용하므로 실제 생성 시각은 23시까지로 제한한다.
                    safe_evening_end = min(
                        profile.evening_end,
                        23,
                    )

                    hour = random.randint(
                        evening_start,
                        safe_evening_end,
                    )
                else:
                    # 예: 22시~02시처럼 자정을 넘기는 직군.
                    # 22~23시 또는 00~02시 중 하나를 정상 패턴으로 생성한다.
                    hour = random.choice(
                        list(range(evening_start, 24))
                        + list(range(0, profile.evening_end + 1))
                    )

            else:
                hour = random.randint(
                    profile.weekday_start,
                    max(
                        profile.weekday_start,
                        profile.weekday_end - 1,
                    ),
                )

        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        ts = day.replace(
            hour=hour,
            minute=minute,
            second=second,
            microsecond=0,
        )

        if start <= ts <= end:
            return ts

    # 거의 발생하지 않는 fallback
    return end - timedelta(minutes=random.randint(1, 120))


def event_kind(profile: UserProfile) -> str:
    usb = profile.usb_probability

    r = random.random()

    if r < usb:
        return "usb"

    r -= usb

    if r < profile.process_ratio:
        return "process"

    r -= profile.process_ratio

    if r < profile.file_ratio:
        return "file"

    return "login"


# ============================================================
# EventCreate used for actual baseline learning
# ============================================================

def make_process_event(
    profile: UserProfile,
    timestamp: datetime,
    process_name: str,
) -> EventCreate:
    return EventCreate(
        user=profile.username,
        event_type="process_execution",
        timestamp=timestamp,
        source=SOURCE_NAME,
        raw_event_id=(
            f"EXH-LEARN-PROC-{profile.username}-"
            f"{int(timestamp.timestamp() * 1000)}"
        ),
        source_ip=profile.ip,
        host=profile.host,
        workstation_name=profile.host,
        logon_type="2",
        login_success=1,
        login_fail_count=0,
        file_access_count=0,
        usb_connected=0,
        process_name=process_name,
        command_line=process_name,
        parent_process=parent_process_for(process_name),
    )


def make_file_event(
    profile: UserProfile,
    timestamp: datetime,
    file_name: str,
) -> EventCreate:
    return EventCreate(
        user=profile.username,
        event_type="file_access",
        timestamp=timestamp,
        source=SOURCE_NAME,
        raw_event_id=(
            f"EXH-LEARN-FILE-{profile.username}-"
            f"{int(timestamp.timestamp() * 1000)}"
        ),
        source_ip=profile.ip,
        host=profile.host,
        workstation_name=profile.host,
        logon_type="2",
        login_success=1,
        login_fail_count=0,
        file_access_count=random.choice([1, 1, 1, 2, 2, 3]),
        usb_connected=0,
        file_name=file_name,
        file_path=f"C:\\WORK\\{profile.department}\\{file_name}",
        file_grade="일반",
    )


def make_login_event(
    profile: UserProfile,
    timestamp: datetime,
) -> EventCreate:
    return EventCreate(
        user=profile.username,
        event_type="login_success",
        timestamp=timestamp,
        source=SOURCE_NAME,
        raw_event_id=(
            f"EXH-LEARN-LOGIN-{profile.username}-"
            f"{int(timestamp.timestamp() * 1000)}"
        ),
        source_ip=profile.ip,
        host=profile.host,
        workstation_name=profile.host,
        logon_type="2",
        login_success=1,
        login_fail_count=0,
        file_access_count=0,
        usb_connected=0,
    )


def learning_timestamps(
    profile: UserProfile,
    history_days: int,
    count: int,
) -> list[datetime]:
    """
    최근 30일 범위에서 반복 관찰이 일어나도록 생성.
    Behavior Change의 반복/시간 조건을 만족시키기 위해
    며칠에 걸쳐 분산시킨다.
    """

    end = datetime.now() - timedelta(days=1)
    start = end - timedelta(days=min(history_days, 30))

    timestamps = [
        choose_work_timestamp(
            profile,
            start,
            end,
        )
        for _ in range(count)
    ]

    return sorted(timestamps)


def seed_learning_events(
    db,
    profile: UserProfile,
    history_days: int,
) -> int:
    timestamps = learning_timestamps(
        profile,
        history_days,
        LEARNING_EVENTS_PER_USER,
    )

    common_processes = [
        item[0]
        for item in sorted(
            profile.processes,
            key=lambda item: item[1],
            reverse=True,
        )[:8]
    ]

    count = 0

    for index, timestamp in enumerate(timestamps):
        # 72개 중 48개는 주요 프로세스 반복
        if index < 48:
            event = make_process_event(
                profile,
                timestamp,
                common_processes[
                    index % len(common_processes)
                ],
            )

        # 16개는 업무 파일 접근
        elif index < 64:
            event = make_file_event(
                profile,
                timestamp,
                profile.files[
                    index % len(profile.files)
                ],
            )

        # 8개는 정상 로그인
        else:
            event = make_login_event(
                profile,
                timestamp,
            )

        process_security_event(
            event,
            db,
            perf_logging=False,
        )

        count += 1

    return count


# ============================================================
# Bulk historical data
# ============================================================

def model_columns() -> set[str]:
    return {
        column.name
        for column in SecurityEvent.__table__.columns
    }


SECURITY_EVENT_COLUMNS = model_columns()


def build_bulk_event(
    profile: UserProfile,
    timestamp: datetime,
    kind: str,
    is_medium_anomaly: bool,
    serial: int,
) -> SecurityEvent:

    event_type = "process_execution"

    process_name = None
    file_name = None
    file_path = None
    file_grade = None
    file_access_count = 0
    usb_connected = 0
    device_name = None
    device_id = None
    command_line = None
    parent_process = None

    login_success = 1
    login_fail_count = 0

    if kind == "process":
        process_name = weighted_process(profile)
        command_line = process_name
        parent_process = parent_process_for(process_name)

    elif kind == "file":
        event_type = "file_access"
        file_name = random.choice(profile.files)
        file_path = f"C:\\WORK\\{profile.department}\\{file_name}"
        file_grade = "일반"
        file_access_count = random.choice(
            [1, 1, 1, 1, 2, 2, 3, 4]
        )

    elif kind == "usb":
        event_type = "usb_connected"
        usb_connected = 1
        device_name = "Corporate USB Storage"
        device_id = f"USBSTOR\\CORP\\{profile.username.upper()}"

    elif kind == "login":
        # 대부분 정상 로그인, 아주 소수 단발 실패.
        failed = random.random() < 0.045

        if failed:
            event_type = "login_failure"
            login_success = 0
            login_fail_count = 1
        else:
            event_type = "login_success"

    # 기본적인 정상 이벤트 분포.
    risk_score = random.uniform(2.5, 12.5)
    anomaly_score = random.uniform(2.0, 28.0)
    risk_level = "LOW"
    reasons = "직군 및 개인 기준선 범위 내 정상 업무 활동"

    # 전시용 검토 대상. HIGH/CRITICAL은 만들지 않는다.
    if is_medium_anomaly:
        anomaly_score = random.uniform(50.5, 71.5)
        risk_score = random.uniform(24.0, 39.0)
        risk_level = "MEDIUM"
        reasons = (
            "개인 기준선 대비 일시적 행동 편차, "
            "전시용 과거 검토 이벤트"
        )

    kwargs = dict(
        user=profile.username,
        event_type=event_type,
        timestamp=timestamp,
        source_ip=profile.ip,
        login_success=login_success,
        login_fail_count=login_fail_count,
        file_name=file_name,
        file_grade=file_grade,
        file_access_count=file_access_count,
        usb_connected=usb_connected,
        process_name=process_name,
        anomaly_score=round(anomaly_score, 2),
        risk_score=round(risk_score, 2),
        risk_level=risk_level,
        reasons=reasons,
    )

    optional = {
        "file_path": file_path,
        "host": profile.host,
        "source": SOURCE_NAME,
        "raw_event_id": (
            f"EXH-BULK-{profile.username}-"
            f"{int(timestamp.timestamp() * 1000)}-{serial}"
        ),
        "device_name": device_name,
        "device_id": device_id,
        "workstation_name": profile.host,
        "logon_type": "2",
        "command_line": command_line,
        "parent_process": parent_process,
    }

    for key, value in optional.items():
        if key in SECURITY_EVENT_COLUMNS:
            kwargs[key] = value

    return SecurityEvent(**kwargs)


def allocate_counts(
    profiles: Iterable[UserProfile],
    total: int,
) -> dict[str, int]:
    profiles = list(profiles)

    weight_sum = sum(p.volume_weight for p in profiles)

    raw = {
        p.username: total * p.volume_weight / weight_sum
        for p in profiles
    }

    result = {
        username: int(value)
        for username, value in raw.items()
    }

    missing = total - sum(result.values())

    # 소수점이 큰 사용자부터 나머지 분배
    order = sorted(
        profiles,
        key=lambda p: raw[p.username] - int(raw[p.username]),
        reverse=True,
    )

    for p in order[:missing]:
        result[p.username] += 1

    return result


def bulk_seed_user(
    db,
    profile: UserProfile,
    count: int,
    history_days: int,
    medium_count: int,
) -> int:

    now = datetime.now() - timedelta(minutes=5)
    start = date_range_start(history_days)

    anomaly_indexes = set(
        random.sample(
            range(count),
            k=min(medium_count, count),
        )
    )

    batch: list[SecurityEvent] = []

    for index in range(count):
        timestamp = choose_work_timestamp(
            profile,
            start,
            now,
        )

        row = build_bulk_event(
            profile=profile,
            timestamp=timestamp,
            kind=event_kind(profile),
            is_medium_anomaly=index in anomaly_indexes,
            serial=index,
        )

        batch.append(row)

        # 한 번에 너무 많은 ORM 객체를 유지하지 않도록 500건 단위 commit.
        if len(batch) >= 500:
            db.add_all(batch)
            db.commit()
            batch.clear()

    if batch:
        db.add_all(batch)
        db.commit()

    return count


# ============================================================
# Reporting / validation
# ============================================================

def behavior_summary(db, username: str) -> dict[str, int]:
    if not table_exists(db, "behavior_change_observations"):
        return {}

    rows = db.execute(
        text(
            """
            SELECT status, COUNT(*) AS cnt
            FROM behavior_change_observations
            WHERE user=:user
            GROUP BY status
            """
        ),
        {"user": username},
    ).mappings().all()

    return {
        str(row["status"]): int(row["cnt"])
        for row in rows
    }


def exhibition_summary(db) -> dict[str, int]:
    usernames = [p.username for p in USERS]

    marks = ",".join(
        f":u{i}" for i in range(len(usernames))
    )

    params = {
        f"u{i}": username
        for i, username in enumerate(usernames)
    }

    def scalar(query: str) -> int:
        return int(
            db.execute(
                text(query),
                params,
            ).scalar_one()
        )

    return {
        "events": scalar(
            f"""
            SELECT COUNT(*)
            FROM security_events
            WHERE user IN ({marks})
            """
        ),
        "medium": scalar(
            f"""
            SELECT COUNT(*)
            FROM security_events
            WHERE user IN ({marks})
              AND risk_level='MEDIUM'
            """
        ),
        "high": scalar(
            f"""
            SELECT COUNT(*)
            FROM security_events
            WHERE user IN ({marks})
              AND risk_level='HIGH'
            """
        ),
        "critical": scalar(
            f"""
            SELECT COUNT(*)
            FROM security_events
            WHERE user IN ({marks})
              AND risk_level='CRITICAL'
            """
        ),
        "anomalies": scalar(
            f"""
            SELECT COUNT(*)
            FROM security_events
            WHERE user IN ({marks})
              AND anomaly_score >= 50
            """
        ),
    }


def process_diversity(db) -> int:
    usernames = [p.username for p in USERS]

    marks = ",".join(
        f":u{i}" for i in range(len(usernames))
    )

    params = {
        f"u{i}": username
        for i, username in enumerate(usernames)
    }

    return int(
        db.execute(
            text(
                f"""
                SELECT COUNT(DISTINCT process_name)
                FROM security_events
                WHERE user IN ({marks})
                  AND process_name IS NOT NULL
                  AND process_name != ''
                """
            ),
            params,
        ).scalar_one()
    )


def print_distribution(counts: dict[str, int]) -> None:
    print()
    print("사용자별 목표 이벤트:")
    print("-" * 72)

    by_username = {
        p.username: p
        for p in USERS
    }

    for username, count in sorted(
        counts.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        profile = by_username[username]

        print(
            f"  {username:<12} "
            f"{count:>5,}건  "
            f"{profile.department:<10} "
            f"{profile.role}"
        )


def dry_run_report(
    target_events: int,
    history_days: int,
) -> None:
    learning_total = len(USERS) * LEARNING_EVENTS_PER_USER
    bulk_total = max(0, target_events - learning_total)

    bulk_counts = allocate_counts(
        USERS,
        bulk_total,
    )

    final_counts = {
        p.username:
            bulk_counts[p.username] + LEARNING_EVENTS_PER_USER
        for p in USERS
    }

    print("=" * 78)
    print("SENTINEL EXHIBITION DATASET v2 - DRY RUN")
    print("=" * 78)
    print(f"목표 가상 이벤트 : {target_events:,}건")
    print(f"기간             : 최근 {history_days}일")
    print(f"가상 사용자      : {len(USERS)}명")
    print(f"실제 시연 사용자 : {REAL_DEMO_USER}")
    print(f"대시보드 사용자  : 총 {len(USERS) + 1}명")
    print(f"예상 MEDIUM      : 약 {round(target_events * MEDIUM_ANOMALY_RATIO):,}건")
    print("HIGH/CRITICAL    : 사전 생성 안 함")

    print_distribution(final_counts)

    all_processes = {
        process
        for p in USERS
        for process, _ in p.processes
    }

    print()
    print(f"프로그램 종류    : 최소 {len(all_processes)}종")
    print("siem_demo        : 변경하지 않음")
    print("CERT 100K        : 변경하지 않음")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL 작품전시회용 30K 현실적 조직 데이터 생성기"
    )

    parser.add_argument(
        "--target-events",
        type=int,
        default=DEFAULT_TARGET_EVENTS,
        help=f"가상 이벤트 목표 건수 (기본 {DEFAULT_TARGET_EVENTS})",
    )

    parser.add_argument(
        "--history-days",
        type=int,
        default=DEFAULT_HISTORY_DAYS,
        help=f"과거 이력 기간 일수 (기본 {DEFAULT_HISTORY_DAYS})",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="DB를 변경하지 않고 구성만 출력",
    )

    args = parser.parse_args()

    if args.target_events < len(USERS) * LEARNING_EVENTS_PER_USER:
        print(
            "[ERROR] --target-events가 너무 작습니다. "
            f"최소 {len(USERS) * LEARNING_EVENTS_PER_USER:,} 이상 필요합니다."
        )
        sys.exit(1)

    if args.history_days < 30:
        print("[ERROR] --history-days는 최소 30일 이상으로 설정하세요.")
        sys.exit(1)

    if args.dry_run:
        dry_run_report(
            args.target_events,
            args.history_days,
        )
        return

    db = SessionLocal()

    try:
        print("=" * 78)
        print("SENTINEL EXHIBITION DATASET v2")
        print("=" * 78)
        print()
        print(f"목표 가상 이벤트 : {args.target_events:,}건")
        print(f"이력 기간         : 최근 {args.history_days}일")
        print(f"가상 사용자       : {len(USERS)}명")
        print(f"실제 시연 사용자  : {REAL_DEMO_USER}")
        print(f"최종 모니터링 규모: 총 {len(USERS) + 1}명")
        print()
        print("보존:")
        print("  - siem_demo 이벤트")
        print("  - siem_demo Behavior Change")
        print("  - siem_demo Endpoint 학습")
        print("  - CERT 100K 데이터")
        print()

        # ----------------------------------------------------
        # 1. User registration
        # ----------------------------------------------------
        print("[1/5] 전시용 사용자 등록/활성화")

        for profile in USERS:
            ensure_monitored_user(db, profile)

        ensure_demo_user_enabled(db)
        db.commit()

        print(f"  가상 사용자 {len(USERS)}명 준비 완료")

        # ----------------------------------------------------
        # 2. Reset synthetic only
        # ----------------------------------------------------
        print()
        print("[2/5] 기존 가상 전시 데이터 초기화")

        for profile in USERS:
            deleted = reset_synthetic_user(
                db,
                profile.username,
            )

            print(
                f"  {profile.username:<12} "
                f"삭제 {deleted:>5,}건"
            )

        db.commit()

        # ----------------------------------------------------
        # 3. Real-pipeline learning
        # ----------------------------------------------------
        print()
        print("[3/5] 직군별 정상 행동 실제 UEBA 학습")

        learning_total = 0

        for profile in USERS:
            count = seed_learning_events(
                db,
                profile,
                args.history_days,
            )

            learning_total += count

            summary = behavior_summary(
                db,
                profile.username,
            )

            print(
                f"  {profile.username:<12} "
                f"{count:>3}건 | "
                f"ACCEPTED={summary.get('ACCEPTED', 0):>2} "
                f"OBS={summary.get('OBSERVING', 0):>2} "
                f"REJ={summary.get('REJECTED', 0):>2}"
            )

        # ----------------------------------------------------
        # 4. Historical bulk data
        # ----------------------------------------------------
        print()
        print("[4/5] 90일 업무 이력 대량 생성")

        bulk_target = args.target_events - learning_total

        bulk_counts = allocate_counts(
            USERS,
            bulk_target,
        )

        medium_total = round(
            args.target_events * MEDIUM_ANOMALY_RATIO
        )

        medium_counts = allocate_counts(
            USERS,
            medium_total,
        )

        for profile in USERS:
            count = bulk_counts[
                profile.username
            ]

            medium_count = medium_counts[
                profile.username
            ]

            inserted = bulk_seed_user(
                db=db,
                profile=profile,
                count=count,
                history_days=args.history_days,
                medium_count=medium_count,
            )

            print(
                f"  {profile.username:<12} "
                f"+{inserted:>5,}건 | "
                f"{profile.category:<10} | "
                f"MEDIUM 약 {medium_count:>3}건"
            )

        # ----------------------------------------------------
        # 5. Validation
        # ----------------------------------------------------
        print()
        print("[5/5] 최종 검증")

        summary = exhibition_summary(db)
        diversity = process_diversity(db)

        print()
        print("=" * 78)
        print("SENTINEL 전시 데이터 생성 완료")
        print("=" * 78)
        print(f"가상 이벤트        : {summary['events']:,}건")
        print(f"이상행동 >= 50     : {summary['anomalies']:,}건")
        print(f"MEDIUM             : {summary['medium']:,}건")
        print(f"HIGH               : {summary['high']:,}건")
        print(f"CRITICAL           : {summary['critical']:,}건")
        print(f"프로그램 종류      : {diversity}종")
        print(f"가상 사용자        : {len(USERS)}명")
        print(f"+ 실제 시연 사용자 : {REAL_DEMO_USER}")
        print(f"대시보드 사용자    : 총 {len(USERS) + 1}명")

        print()
        print("정상 행동 차별화:")
        print("  개발자:")
        print("    PyCharm / VS Code / Python / Git / Node / Docker / Terminal")
        print("    야간 작업과 주말 작업 일부 정상")
        print()
        print("  IT/보안:")
        print("    PowerShell / Terminal / MMC / RDP / Wireshark / WinSCP")
        print("    야간/주말 관리 작업 일부 정상")
        print()
        print("  사무/인사/재무:")
        print("    Excel / Word / Outlook / Teams / PDF")
        print("    평일 주간 중심, 야간/주말 매우 드묾")
        print()
        print("  디자인/기획:")
        print("    Figma / Photoshop / Illustrator / PowerPoint / Office")
        print("    저녁 작업 일부 정상")
        print()
        print("  관리자:")
        print("    Outlook / Teams / PowerPoint / Excel / 보고서")
        print("    08~22시 활동 가능")

        print()
        print("전시 당일:")
        print(
            "  HIGH / CRITICAL은 미리 채우지 않았으므로 "
            "siem_demo 공격 시나리오가 발생하면 "
            "실시간 사고가 명확하게 튀어 보입니다."
        )

    except Exception as error:
        db.rollback()

        print()
        print("=" * 78)
        print("[ERROR] 데이터 생성 중 오류 발생")
        print("=" * 78)
        print(type(error).__name__, error)
        print()
        print(
            "이 스크립트는 재실행 가능하게 설계되어 있습니다. "
            "가상 사용자 데이터만 다시 초기화하고 구성합니다."
        )

        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
