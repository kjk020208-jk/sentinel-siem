from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    DateTime,
    Text
)
from datetime import datetime

from server.database import Base


# =================================================
# 보안 이벤트
# =================================================

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user = Column(
        String,
        index=True
    )

    event_type = Column(
        String,
        index=True
    )

    timestamp = Column(
        DateTime,
        default=datetime.now
    )

    # 공통 이벤트 메타데이터
    # Windows 실시간 로그와 공개 데이터셋을 같은 구조로 저장하기 위한 필드다.
    host = Column(
        String,
        nullable=True,
        index=True
    )

    source = Column(
        String,
        nullable=True,
        index=True
    )

    raw_event_id = Column(
        String,
        nullable=True
    )

    source_ip = Column(
        String,
        nullable=True
    )

    login_success = Column(
        Integer,
        nullable=True
    )

    login_fail_count = Column(
        Integer,
        default=0
    )

    file_name = Column(
        String,
        nullable=True
    )

    file_path = Column(
        String,
        nullable=True
    )

    file_grade = Column(
        String,
        nullable=True
    )

    file_access_count = Column(
        Integer,
        default=0
    )

    usb_connected = Column(
        Integer,
        default=0
    )

    device_name = Column(
        String,
        nullable=True
    )

    device_id = Column(
        String,
        nullable=True
    )

    process_name = Column(
        String,
        nullable=True
    )

    anomaly_score = Column(
        Float,
        default=0.0
    )

    risk_score = Column(
        Float,
        default=0.0
    )

    risk_level = Column(
        String,
        default="LOW"
    )

    reasons = Column(
        Text,
        nullable=True
    )


# =================================================
# 모니터링 대상 사용자
# =================================================

class MonitoredUser(Base):
    __tablename__ = "monitored_users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    # Windows 계정명
    username = Column(
        String,
        unique=True,
        index=True,
        nullable=False
    )

    # 관리자 화면에서 표시할 이름
    display_name = Column(
        String,
        nullable=True
    )

    # 부서
    department = Column(
        String,
        nullable=True
    )

    # 직무
    role = Column(
        String,
        nullable=True
    )

    # 1 = 모니터링
    # 0 = 모니터링 중지
    monitoring_enabled = Column(
        Integer,
        default=1,
        nullable=False
    )

    # 사용자 등록 시간
    created_at = Column(
        DateTime,
        default=datetime.now,
        nullable=False
    )