from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from time import perf_counter
from typing import Optional
import os
import shutil
import tempfile
import base64
import secrets
from pathlib import Path

from fastapi import (
    FastAPI,
    Depends,
    UploadFile,
    File,
    Form,
    HTTPException,
    Header,
    Request
)
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from server.database import Base, engine, get_db
from server.models import (
    SecurityEvent,
    MonitoredUser
)
from server.risk_engine import (
    calculate_rule_risk,
    calculate_final_risk
)
from server.ml_engine import detector
from server.sequence_engine import analyze_sequence
from server.pii_engine import analyze_document
from server.dynamic_risk_engine import (
    get_dynamic_user_risk_profile,
    calculate_dynamic_user_risk,
)
from server.baseline_engine import (
    analyze_user_baseline,
    analyze_peer_group_baseline,
    calculate_adaptive_compensation,
    get_user_behavior_profile,
    get_peer_group_profile
)
from server.extended_context_engine import (
    analyze_extended_context,
    evaluate_extended_behavior_changes,
    persist_event_context,
)
from server.llm_engine import (
    analyze_security_incident,
    analyze_incident_with_ai
)
from server.incident_engine import (
    SecurityIncident,
    correlate_security_incident,
    get_incidents,
    get_incident,
    update_incident_status
)
from server.playbook_engine import (
    ResponsePlaybookExecution,
    get_or_create_playbook,
    update_playbook_step
)
from server.risk_explanation_engine import (
    EventRiskExplanation,
    build_risk_explanation,
    save_risk_explanation,
    get_risk_explanation
)
from server.schema_migration import migrate_security_event_schema
from server.change_verification_engine import (
    evaluate_behavior_change,
    get_behavior_changes,
    update_behavior_change_decision,
)
from server.endpoint_context_engine import (
    analyze_endpoint_context,
    persist_endpoint_context,
    observe_endpoint_changes,
    get_endpoint_event_context,
    get_endpoint_profile,
)


Base.metadata.create_all(bind=engine)
migrate_security_event_schema(engine)

app = FastAPI(
    title="Insider Threat Detection API",
    description="내부자 위협 탐지 및 대응 플랫폼",
    version="0.9"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://sentinel-siem-production.up.railway.app",
        "http://localhost:5173"
        "https://sentineljk.co.kr",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# -------------------------------------------------
# Deployment security / dashboard hosting
# -------------------------------------------------
# Production environment variables:
#   SENTINEL_AGENT_TOKEN      Agent -> /events authentication token
#   SENTINEL_ADMIN_USER       Dashboard/API HTTP Basic username
#   SENTINEL_ADMIN_PASSWORD   Dashboard/API HTTP Basic password
#   SENTINEL_DASHBOARD_DIR    React production build directory
#
# If the admin variables are omitted, local development remains backward
# compatible. In production, configure all three security variables.

SENTINEL_AGENT_TOKEN = os.getenv("SENTINEL_AGENT_TOKEN", "").strip()
SENTINEL_ADMIN_USER = os.getenv("SENTINEL_ADMIN_USER", "").strip()
SENTINEL_ADMIN_PASSWORD = os.getenv("SENTINEL_ADMIN_PASSWORD", "")
DASHBOARD_DIR = Path(
    os.getenv("SENTINEL_DASHBOARD_DIR", "dashboard_dist")
).resolve()


def _admin_credentials_valid(authorization: str | None) -> bool:
    if not SENTINEL_ADMIN_USER or not SENTINEL_ADMIN_PASSWORD:
        return True

    if not authorization or not authorization.startswith("Basic "):
        return False

    try:
        encoded = authorization.split(" ", 1)[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False

    return (
        secrets.compare_digest(username, SENTINEL_ADMIN_USER)
        and secrets.compare_digest(password, SENTINEL_ADMIN_PASSWORD)
    )


@app.middleware("http")
async def sentinel_admin_auth(request: Request, call_next):
    # Browser preflight and health checks stay reachable.
    if request.method == "OPTIONS" or request.url.path == "/health":
        return await call_next(request)

    # Agent ingestion has its own X-Agent-Token authentication.
    if request.method == "POST" and request.url.path == "/events":
        return await call_next(request)

    # Local development remains compatible until admin credentials are set.
    if not SENTINEL_ADMIN_USER or not SENTINEL_ADMIN_PASSWORD:
        return await call_next(request)

    if not _admin_credentials_valid(request.headers.get("Authorization")):
        return JSONResponse(
            status_code=401,
            content={"detail": "SENTINEL 관리자 인증이 필요합니다."},
            headers={"WWW-Authenticate": 'Basic realm="SENTINEL SOC"'},
        )

    return await call_next(request)


# React production build is served by the same FastAPI origin.
# This avoids exposing a separate frontend origin and keeps API calls same-origin.
app.mount(
    "/dashboard",
    StaticFiles(directory=str(DASHBOARD_DIR), html=True, check_dir=False),
    name="dashboard",
)


class EventCreate(BaseModel):
    user: str
    event_type: str

    # 공통 이벤트 메타데이터
    # timestamp가 없으면 실시간 수집 이벤트로 보고 서버 수신 시각을 사용한다.
    timestamp: Optional[datetime] = None
    host: Optional[str] = None
    source: Optional[str] = None
    raw_event_id: Optional[str] = None

    # Windows 이벤트에 기록된 원격 접속 원본 IP
    source_ip: Optional[str] = None

    # SENTINEL Agent 자체의 실제 단말/네트워크 식별 정보
    agent_id: Optional[str] = None
    endpoint_ip: Optional[str] = None
    endpoint_network: Optional[str] = None

    login_success: Optional[int] = None
    login_fail_count: int = 0

    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_grade: Optional[str] = None
    file_access_count: int = 0

    usb_connected: int = 0
    device_name: Optional[str] = None
    device_id: Optional[str] = None

    process_name: Optional[str] = None
    workstation_name: Optional[str] = None
    logon_type: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None


class MonitoredUserCreate(BaseModel):
    username: str
    display_name: Optional[str] = None
    department: Optional[str] = None
    role: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    status: str


class PlaybookStepUpdate(BaseModel):
    action: str
    note: Optional[str] = None


class BehaviorChangeDecision(BaseModel):
    action: str
    note: Optional[str] = None


def get_risk_level(score):
    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 24:
        return "MEDIUM"

    else:
        return "LOW"


def process_security_event(
    event: EventCreate,
    db: Session,
    perf_logging: bool = True
):
    total_start = perf_counter()

    # 공개 데이터셋은 원래 발생 시각을 보존해야 시간대/행동순서 분석이 가능하다.
    # 실시간 Collector처럼 timestamp를 보내지 않는 경우에만 서버 현재 시각을 사용한다.
    now = event.timestamp or datetime.now()

    # --------------------------------
    # Endpoint / Agent Context
    # --------------------------------
    # source_ip(원격 접속 원본)와 endpoint_ip(감시 단말 IP)를 분리한다.
    # DHCP에 의한 동일 네트워크 내 IP 변경은 위험으로 가중하지 않고,
    # 승인된 네트워크/Agent에서 벗어나는 변화만 보조 위험 신호로 사용한다.
    endpoint_context_score, endpoint_context_reasons, endpoint_context = (
        analyze_endpoint_context(
            db=db,
            event=event,
            reference_time=now,
        )
    )

    # --------------------------------
    # 1. Rule 기반 분석
    # --------------------------------

    step_start = perf_counter()

    rule_score, _, rule_reasons = calculate_rule_risk(
        event
    )

    rule_score += endpoint_context_score
    rule_reasons = list(rule_reasons) + list(endpoint_context_reasons)

    rule_time = perf_counter() - step_start

    # --------------------------------
    # 2. Isolation Forest 분석
    # --------------------------------

    step_start = perf_counter()

    anomaly_score, is_anomaly = detector.analyze(
        login_fail_count=event.login_fail_count,
        file_access_count=event.file_access_count,
        usb_connected=event.usb_connected,
        hour=now.hour
    )

    ml_time = perf_counter() - step_start

    reasons = list(rule_reasons)

    if is_anomaly:
        reasons.append(
            "Isolation Forest 사용자 행동 이상 탐지"
        )

    # --------------------------------
    # 3. Adaptive Personal Baseline 분석
    # --------------------------------

    step_start = perf_counter()

    baseline_score, baseline_reasons = (
        analyze_user_baseline(
            db=db,
            user=event.user,
            current_ip=event.source_ip,
            current_hour=now.hour,
            current_file_access_count=(
                event.file_access_count
            ),
            current_process_name=(
                event.process_name
            ),
            current_usb_connected=(
                event.usb_connected
            ),
            current_timestamp=now
        )
    )

    baseline_time = perf_counter() - step_start

    reasons.extend(
        baseline_reasons
    )

    # --------------------------------
    # 4. Peer Group UEBA 분석
    #
    # Stage 1: 검증용 보조 신호.
    # 아직 peer_score를 최종 Risk Score에 합산하지 않는다.
    # --------------------------------

    step_start = perf_counter()

    peer_result = analyze_peer_group_baseline(
        db=db,
        user=event.user,
        current_ip=event.source_ip,
        current_hour=now.hour,
        current_file_access_count=event.file_access_count,
        current_process_name=event.process_name,
        current_usb_connected=event.usb_connected,
        current_timestamp=now
    )

    peer_time = perf_counter() - step_start

    peer_score = float(
        peer_result.get("score", 0) or 0
    )

    peer_group_available = bool(
        peer_result.get(
            "group_available",
            False
        )
    )

    # Peer Group은 개인 기준선을 대체하지 않는 보조 신호다.
    #
    # Peer Risk Guard:
    # - Peer 기준선이 부족하면 반영하지 않는다.
    # - 시간대/프로세스 차이만으로 LOW -> MEDIUM 오탐을 만들지 않는다.
    # - 파일 접근량 급증, USB 등 강한 행동 이탈이 있거나
    #   Peer Score가 40 이상으로 복합 이탈이 형성될 때만 반영한다.
    peer_reasons = (
        peer_result.get("reasons", []) or []
    )

    strong_peer_evidence = any(
        evidence in reason
        for reason in peer_reasons
        for evidence in [
            "파일 접근량",
            "USB"
        ]
    )

    peer_risk_guard_passed = (
        peer_group_available
        and (
            strong_peer_evidence
            or peer_score >= 40
        )
    )

    peer_contribution = (
        round(peer_score * 0.2, 2)
        if peer_risk_guard_passed
        else 0.0
    )

    peer_reasons = (
        peer_result.get("reasons", []) or []
    )

    if peer_result.get("group_available", False):
        reasons.extend(peer_reasons)




    # --------------------------------
    # 5. 현재 이벤트 DB 저장
    # --------------------------------

    step_start = perf_counter()

    db_event = SecurityEvent(
        user=event.user,
        event_type=event.event_type,
        timestamp=now,
        host=event.host,
        source=event.source or "api",
        raw_event_id=event.raw_event_id,
        source_ip=event.source_ip,
        login_success=event.login_success,
        login_fail_count=event.login_fail_count,
        file_name=event.file_name,
        file_path=event.file_path,
        file_grade=event.file_grade,
        file_access_count=event.file_access_count,
        usb_connected=event.usb_connected,
        device_name=event.device_name,
        device_id=event.device_id,
        process_name=event.process_name,

        anomaly_score=anomaly_score,

        risk_score=0,
        risk_level="LOW",
        reasons=""
    )

    db.add(db_event)
    db.commit()
    db.refresh(db_event)

    # SecurityEvent 원본 테이블을 깨지 않고 Agent/Endpoint 맥락을 보조 테이블에 저장한다.
    persist_endpoint_context(
        db=db,
        event_id=db_event.id,
        event=event,
        reference_time=now,
    )

    db_insert_time = perf_counter() - step_start

    # --------------------------------
    # 확장 접속/행동 맥락 분석
    # --------------------------------
    extended_score, extended_reasons, _ = analyze_extended_context(
        db=db,
        event=event,
        reference_time=now,
    )

    if extended_reasons:
        reasons.extend(extended_reasons)
        rule_reasons.extend(extended_reasons)

    rule_score += extended_score


    # --------------------------------
    # 6. Sequence 분석
    # --------------------------------

    step_start = perf_counter()

    sequence_score, sequence_reasons = (
        analyze_sequence(
            db,
            event.user,
            reference_time=now
        )
    )

    sequence_time = perf_counter() - step_start

    reasons.extend(
        sequence_reasons
    )

    # --------------------------------
    # 7. Adaptive Risk Compensation
    # --------------------------------

    step_start = perf_counter()

    adaptive_result = (
        calculate_adaptive_compensation(
            db=db,
            user=event.user,
            current_hour=now.hour,
            current_process_name=(
                event.process_name
            ),
            current_timestamp=now,
            rule_reasons=rule_reasons,
            baseline_score=baseline_score,
            sequence_score=sequence_score,
            event_type=event.event_type,
            file_grade=event.file_grade,
            file_access_count=(
                event.file_access_count
            ),
            usb_connected=(
                event.usb_connected
            ),
            login_fail_count=(
                event.login_fail_count
            )
        )
    )

    adaptive_compensation = float(
        adaptive_result.get(
            "score",
            0
        )
        or 0
    )

    adaptive_reasons = (
        adaptive_result.get(
            "reasons",
            []
        )
        or []
    )

    reasons.extend(
        adaptive_reasons
    )

    compensation_time = (
        perf_counter()
        - step_start
    )

    # --------------------------------
    # 8. Rule + ML 기본 위험도
    # --------------------------------

    step_start = perf_counter()

    base_score, _ = calculate_final_risk(
        rule_score,
        anomaly_score
    )

    # --------------------------------
    # 9. Baseline + Sequence + Peer Group + Adaptive 보정
    # --------------------------------

    final_score = (
        base_score
        + baseline_score * 0.3
        + sequence_score * 0.4
        + peer_contribution
        - adaptive_compensation
    )

    final_score = round(
        max(
            min(final_score, 100),
            0
        ),
        2
    )

    score_before_floor = final_score
    floor_applied = False
    floor_reason = None

    # --------------------------------
    # 10. Sequence 최소 위험도
    # --------------------------------

    if sequence_score >= 100:
        final_score = max(
            final_score,
            90
        )

    elif sequence_score >= 80:
        final_score = max(
            final_score,
            80
        )

    elif sequence_score >= 60:
        final_score = max(
            final_score,
            65
        )

    elif sequence_score >= 40:
        final_score = max(
            final_score,
            45
        )

    # --------------------------------
    # Baseline 최소 위험도
    # --------------------------------

    if baseline_score >= 60:
        final_score = max(
            final_score,
            60
        )

    elif baseline_score >= 30:
        final_score = max(
            final_score,
            30
        )

    if final_score > score_before_floor:
        floor_applied = True

        if sequence_score >= 100:
            floor_reason = "Sequence Score 100 이상 → Event Risk 최소 90"
        elif sequence_score >= 80:
            floor_reason = "Sequence Score 80 이상 → Event Risk 최소 80"
        elif sequence_score >= 60:
            floor_reason = "Sequence Score 60 이상 → Event Risk 최소 65"
        elif baseline_score >= 60:
            floor_reason = "Personal Baseline Score 60 이상 → Event Risk 최소 60"
        elif sequence_score >= 40:
            floor_reason = "Sequence Score 40 이상 → Event Risk 최소 45"
        elif baseline_score >= 30:
            floor_reason = "Personal Baseline Score 30 이상 → Event Risk 최소 30"

    # --------------------------------
    # 11. 최종 위험 등급
    # --------------------------------

    risk_level = get_risk_level(
        final_score
    )

    calculation_time = perf_counter() - step_start

    # --------------------------------
    # 12. DB 최종 업데이트
    # --------------------------------

    step_start = perf_counter()

    db_event.risk_score = final_score
    db_event.risk_level = risk_level
    db_event.reasons = ", ".join(
        reasons
    )

    db.commit()
    db.refresh(db_event)

    # --------------------------------
    # 12-1. Behavior Change Verification
    # --------------------------------
    # HOST / WORKSTATION 중복 검증 방지
    db_event.workstation_name = getattr(
        event,
        "workstation_name",
        None
    )

    change_results = evaluate_behavior_change(
        db=db,
        event=db_event
    )

    if change_results:
        for change in change_results:
            reasons.append(
                "행동 변화 검증: "
                f"{change['type']}={change['value']} / "
                f"{change['status']} / "
                f"{change['reason']}"
            )

        db_event.reasons = ", ".join(reasons)
        db.commit()
        db.refresh(db_event)


    # --------------------------------
    # 확장 행동 변화 검증
    # --------------------------------
    extended_change_results = evaluate_extended_behavior_changes(
        db=db,
        event=event,
        risk_score=final_score,
        risk_level=risk_level,
        reasons=reasons,
        reference_time=now,
    )

    if extended_change_results:
        for change in extended_change_results:
            reasons.append(
                "행동 변화 검증: "
                f"{change['type']}={change['value']} / "
                f"{change['status']} / "
                f"{change['reason']}"
            )

        db_event.reasons = ", ".join(reasons)
        db.commit()
        db.refresh(db_event)

    existing_change_results = (
        change_results
        if "change_results" in locals()
        else []
    )

    persist_event_context(
        db=db,
        db_event=db_event,
        event=event,
        change_results=(
            list(existing_change_results)
            + list(extended_change_results)
        ),
    )

    endpoint_change_results = observe_endpoint_changes(
        db=db,
        event=event,
        risk_score=final_score,
        reference_time=now,
    )

    if endpoint_change_results:
        for change in endpoint_change_results:
            reasons.append(
                "Endpoint 행동 변화: "
                f"{change['type']}={change['value']} / "
                f"{change['status']} / {change['reason']}"
            )
        db_event.reasons = ", ".join(reasons)
        db.commit()
        db.refresh(db_event)

    risk_explanation = build_risk_explanation(
        event_id=db_event.id,
        rule_score=rule_score,
        anomaly_score=anomaly_score,
        base_score=base_score,
        baseline_score=baseline_score,
        sequence_score=sequence_score,
        peer_score=peer_score,
        peer_contribution=peer_contribution,
        peer_risk_guard_passed=peer_risk_guard_passed,
        adaptive_compensation=adaptive_compensation,
        adaptive_applied=bool(adaptive_result.get("applied", False)),
        adaptive_confidence_level=adaptive_result.get("confidence_level"),
        score_before_floor=score_before_floor,
        final_score=final_score,
        risk_level=risk_level,
        floor_applied=floor_applied,
        floor_reason=floor_reason,
        reasons=reasons
    )

    save_risk_explanation(
        db=db,
        event_id=db_event.id,
        explanation=risk_explanation
    )

    db_update_time = perf_counter() - step_start

    # --------------------------------
    # 13. Dynamic User Risk
    # --------------------------------
    # 현재 이벤트의 Event Risk 저장이 끝난 뒤 사용자 전체 위험 상태를 계산한다.
    # 이 값은 Event Risk에 다시 더하지 않아 자기증폭을 방지한다.
    step_start = perf_counter()

    dynamic_risk = calculate_dynamic_user_risk(
        db=db,
        user=event.user,
        reference_time=db_event.timestamp
    )

    dynamic_risk_time = perf_counter() - step_start

    # --------------------------------
    # 14. Incident Correlation
    # --------------------------------
    # Event Risk / Dynamic User Risk 계산을 변경하지 않는다.
    # 저장이 완료된 SecurityEvent들을 별도의 사고 단위로 상관분석한다.
    step_start = perf_counter()

    try:
        incident_result = correlate_security_incident(
            db=db,
            user=event.user,
            reference_time=db_event.timestamp
        )

        incident_error = None

    except Exception as error:
        # Incident 계층 오류가 이미 성공한 이벤트 수집을 실패시키지 않도록 분리한다.
        incident_result = {
            "incident_created": False,
            "incident_updated": False,
            "incident": None
        }

        incident_error = str(error)

    incident_time = perf_counter() - step_start
    total_time = perf_counter() - total_start

    if perf_logging:
        print()
        print(
            f"[PERF] user={event.user} "
            f"event={event.event_type}"
        )
        print(f"[PERF] Rule       : {rule_time:.4f}s")
        print(f"[PERF] ML         : {ml_time:.4f}s")
        print(f"[PERF] Baseline   : {baseline_time:.4f}s")
        print(f"[PERF] Peer Group : {peer_time:.4f}s")
        print(
            f"[PERF] Peer Score : {peer_score:.2f} "
            f"(guard={peer_risk_guard_passed}, "
            f"contribution +{peer_contribution:.2f})"
        )
        print(f"[PERF] DB Insert  : {db_insert_time:.4f}s")
        print(f"[PERF] Sequence   : {sequence_time:.4f}s")
        print(f"[PERF] Adaptive   : {compensation_time:.4f}s")
        print(f"[PERF] Calculate  : {calculation_time:.4f}s")
        print(f"[PERF] DB Update  : {db_update_time:.4f}s")
        print(
            f"[PERF] User Risk  : {dynamic_risk_time:.4f}s "
            f"(score={dynamic_risk['dynamic_risk_score']:.2f}, "
            f"level={dynamic_risk['dynamic_risk_level']})"
        )
        print(
            f"[PERF] Incident   : {incident_time:.4f}s "
            f"(created={incident_result.get('incident_created', False)}, "
            f"updated={incident_result.get('incident_updated', False)})"
        )
        print(f"[PERF] TOTAL      : {total_time:.4f}s")
        print()

    return {
        "event_id": db_event.id,
        "rule_score": rule_score,
        "anomaly_score": anomaly_score,
        "is_anomaly": is_anomaly,
        "baseline_score": baseline_score,
        "endpoint_context_score": endpoint_context_score,
        "endpoint_context_reasons": endpoint_context_reasons,
        "endpoint_context": endpoint_context,
        "peer_score": peer_score,
        "peer_contribution": peer_contribution,
        "peer_weight": 0.2,
        "peer_risk_guard_passed": peer_risk_guard_passed,
        "peer_strong_evidence": strong_peer_evidence,
        "peer_reasons": peer_reasons,
        "peer_group_available": peer_group_available,
        "peer_group_key": peer_result.get("group_key"),
        "peer_user_count": int(
            peer_result.get("peer_user_count", 0) or 0
        ),
        "peer_event_count": int(
            peer_result.get("peer_event_count", 0) or 0
        ),
        "peer_users": (
            peer_result.get("peer_users", []) or []
        ),
        "adaptive_compensation": (
            adaptive_compensation
        ),
        "adaptive_compensation_applied": (
            bool(
                adaptive_result.get(
                    "applied",
                    False
                )
            )
        ),
        "adaptive_confidence_level": (
            adaptive_result.get(
                "confidence_level"
            )
        ),
        "sequence_score": sequence_score,
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_explanation": risk_explanation,
        "behavior_changes": change_results,

        # Dynamic User Risk는 개별 Event Risk와 별도의 사용자 상태값이다.
        "user_risk_score": dynamic_risk[
            "dynamic_risk_score"
        ],
        "user_risk_level": dynamic_risk[
            "dynamic_risk_level"
        ],
        "user_risk_event_count": dynamic_risk[
            "event_count"
        ],
        "user_risk_risk_event_count": dynamic_risk[
            "risk_event_count"
        ],
        "user_risk_cluster_count": dynamic_risk[
            "cluster_count"
        ],
        "user_risk_contributing_cluster_count": (
            dynamic_risk.get(
                "contributing_cluster_count",
                0
            )
        ),
        "user_risk_reason": dynamic_risk[
            "reason"
        ],

        # Incident Correlation은 Event Risk와 별도의 사고 분석 계층이다.
        "incident_created": incident_result.get(
            "incident_created",
            False
        ),
        "incident_updated": incident_result.get(
            "incident_updated",
            False
        ),
        "incident": incident_result.get(
            "incident"
        ),
        "incident_error": incident_error,

        "reasons": reasons
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "SENTINEL",
        "dashboard_path": "/dashboard/",
    }


@app.get("/")
def root():
    return {
        "status": "running",
        "message": "Insider Threat Detection Server"
    }


@app.post("/events")
def create_event(
    event: EventCreate,
    db: Session = Depends(get_db),
    x_agent_token: Optional[str] = Header(default=None, alias="X-Agent-Token")
):
    # Production Agent authentication.
    # If SENTINEL_AGENT_TOKEN is configured, unauthenticated collectors are rejected.
    if SENTINEL_AGENT_TOKEN:
        if not x_agent_token or not secrets.compare_digest(
            x_agent_token, SENTINEL_AGENT_TOKEN
        ):
            raise HTTPException(
                status_code=401,
                detail="유효하지 않은 SENTINEL Agent Token입니다."
            )
    # --------------------------------
    # 모니터링 사용자 검사
    #
    # Collector가 전송하는 /events 요청은
    # 관리자가 등록하고 활성화한 사용자만
    # 분석 및 저장한다.
    #
    # /demo/normal, /demo/attack 등은
    # process_security_event()를 직접 호출하므로
    # 기존 시연 기능에는 영향을 주지 않는다.
    # --------------------------------

    monitored_user = (
        db.query(MonitoredUser)
        .filter(
            MonitoredUser.username == event.user
        )
        .first()
    )

    if not monitored_user:
        raise HTTPException(
            status_code=403,
            detail=(
                f"모니터링 대상으로 등록되지 않은 사용자입니다: "
                f"{event.user}"
            )
        )

    if not monitored_user.monitoring_enabled:
        raise HTTPException(
            status_code=403,
            detail=(
                f"모니터링이 비활성화된 사용자입니다: "
                f"{event.user}"
            )
        )

    result = process_security_event(
        event,
        db
    )

    return {
        "message": "Event analyzed and stored",
        "monitoring_user": event.user,
        **result
    }



# -------------------------------------------------
# Presentation Demo Reset
# -------------------------------------------------

@app.post("/demo/reset-siem-demo")
def reset_siem_demo_attack_data(
    db: Session = Depends(get_db)
):
    """
    발표용 siem_demo 초기화.

    삭제:
    - 실제 시연 중 생성된 Event
    - Incident
    - Playbook
    - 해당 Event Context / Risk Explanation

    유지:
    - Monitored User
    - Behavior Change 학습 상태
    - Endpoint 학습 상태
    - presentation_baseline 정상 이벤트

    추가:
    - 정상 Baseline 이벤트가 부족하면 30건까지 자동 보충
    """

    from datetime import timedelta
    from sqlalchemy import text

    target_user = "siem_demo"
    baseline_source = "presentation_baseline"
    baseline_target_count = 120

    def table_exists(name):
        return db.execute(
            text("""
                SELECT 1
                FROM sqlite_master
                WHERE type='table'
                  AND name=:name
            """),
            {"name": name},
        ).first() is not None

    try:
        # -----------------------------------------
        # 1. 삭제 대상 이벤트:
        # presentation_baseline은 절대 삭제하지 않음
        # -----------------------------------------
        removable_event_ids = []

        if table_exists("security_events"):
            removable_event_ids = [
                int(row[0])
                for row in db.execute(
                    text("""
                        SELECT id
                        FROM security_events
                        WHERE user=:user
                          AND COALESCE(source, '') != :baseline_source
                    """),
                    {
                        "user": target_user,
                        "baseline_source": baseline_source,
                    },
                ).all()
            ]

        incident_ids = []

        if table_exists("security_incidents"):
            incident_ids = [
                int(row[0])
                for row in db.execute(
                    text("""
                        SELECT id
                        FROM security_incidents
                        WHERE user=:user
                    """),
                    {"user": target_user},
                ).all()
            ]

        deleted = {
            "event_risk_explanations": 0,
            "response_playbook_executions": 0,
            "event_context": 0,
            "security_incidents": 0,
            "security_events": 0,
        }

        # -----------------------------------------
        # 2. 삭제 대상 Event의 Risk Explanation
        # -----------------------------------------
        if (
            removable_event_ids
            and table_exists("event_risk_explanations")
        ):
            marks = ",".join(
                f":event_{i}"
                for i in range(len(removable_event_ids))
            )

            params = {
                f"event_{i}": event_id
                for i, event_id in enumerate(removable_event_ids)
            }

            result = db.execute(
                text(
                    "DELETE FROM event_risk_explanations "
                    f"WHERE event_id IN ({marks})"
                ),
                params,
            )

            deleted["event_risk_explanations"] = int(
                result.rowcount or 0
            )

        # -----------------------------------------
        # 3. Playbook 삭제
        # -----------------------------------------
        if (
            incident_ids
            and table_exists("response_playbook_executions")
        ):
            marks = ",".join(
                f":incident_{i}"
                for i in range(len(incident_ids))
            )

            params = {
                f"incident_{i}": incident_id
                for i, incident_id in enumerate(incident_ids)
            }

            result = db.execute(
                text(
                    "DELETE FROM response_playbook_executions "
                    f"WHERE incident_id IN ({marks})"
                ),
                params,
            )

            deleted["response_playbook_executions"] = int(
                result.rowcount or 0
            )

        # -----------------------------------------
        # 4. 실제 시연 Event Context만 삭제
        # baseline context는 유지
        # -----------------------------------------
        if (
            removable_event_ids
            and table_exists("event_context")
        ):
            marks = ",".join(
                f":context_event_{i}"
                for i in range(len(removable_event_ids))
            )

            params = {
                f"context_event_{i}": event_id
                for i, event_id in enumerate(removable_event_ids)
            }

            result = db.execute(
                text(
                    "DELETE FROM event_context "
                    f"WHERE event_id IN ({marks})"
                ),
                params,
            )

            deleted["event_context"] = int(
                result.rowcount or 0
            )

        # -----------------------------------------
        # 5. Incident 삭제
        # -----------------------------------------
        if table_exists("security_incidents"):
            result = db.execute(
                text("""
                    DELETE FROM security_incidents
                    WHERE user=:user
                """),
                {"user": target_user},
            )

            deleted["security_incidents"] = int(
                result.rowcount or 0
            )

        # -----------------------------------------
        # 6. 실제 시연 이벤트만 삭제
        # -----------------------------------------
        if table_exists("security_events"):
            result = db.execute(
                text("""
                    DELETE FROM security_events
                    WHERE user=:user
                      AND COALESCE(source, '') != :baseline_source
                """),
                {
                    "user": target_user,
                    "baseline_source": baseline_source,
                },
            )

            deleted["security_events"] = int(
                result.rowcount or 0
            )

        # -----------------------------------------
        # 7. 사용자 등록 유지 + 활성화
        # -----------------------------------------
        monitored_user = None

        if table_exists("monitored_users"):
            db.execute(
                text("""
                    UPDATE monitored_users
                       SET monitoring_enabled=1
                     WHERE username=:user
                """),
                {"user": target_user},
            )

            monitored_user = (
                db.query(MonitoredUser)
                .filter(MonitoredUser.username == target_user)
                .first()
            )

        db.commit()

        # -----------------------------------------
        # 7-1. 발표용 정상 행동 화이트리스트 보장
        #
        # presentation_baseline 30건이 사용하는
        # IP / PROCESS는 정상 행동으로 수동 승인한다.
        #
        # manual_override=1인 ACCEPTED 항목은
        # Behavior Change 상태만 정상으로 유지하며,
        # Rule / Sequence / Incident 탐지는 그대로 작동한다.
        # -----------------------------------------
        if table_exists("behavior_change_observations"):
            normal_changes = [
                # 실제 시연 PC에서 정상적으로 사용되는 네트워크
                ("IP", "127.0.0.1"),
                ("IP", "172.20.10.13"),

                # IT / 사무 업무에서 반복적으로 사용하는 정상 프로세스
                ("PROCESS", "chrome.exe"),
                ("PROCESS", "code.exe"),
                ("PROCESS", "notepad.exe"),
                ("PROCESS", "winword.exe"),
                ("PROCESS", "excel.exe"),
                ("PROCESS", "outlook.exe"),
                ("PROCESS", "acrord32.exe"),
            ]

            whitelist_now = datetime.now()

            for change_type, change_value in normal_changes:
                existing = db.execute(
                    text("""
                        SELECT id
                        FROM behavior_change_observations
                        WHERE user=:user
                          AND change_type=:change_type
                          AND change_value=:change_value
                    """),
                    {
                        "user": target_user,
                        "change_type": change_type,
                        "change_value": change_value,
                    },
                ).mappings().first()

                if existing:
                    db.execute(
                        text("""
                            UPDATE behavior_change_observations
                               SET status='ACCEPTED',
                                   manual_override=1,
                                   manual_note=:note,
                                   decision_reason=:reason,
                                   decided_at=:decided_at,
                                   risky_context_count=0,
                                   max_risk_score=0
                             WHERE id=:id
                        """),
                        {
                            "id": existing["id"],
                            "note": "발표용 정상 Baseline 행동",
                            "reason": (
                                "SOC 관리자 수동 승인: "
                                "발표용 정상 Baseline 행동"
                            ),
                            "decided_at": whitelist_now,
                        },
                    )

                else:
                    db.execute(
                        text("""
                            INSERT INTO behavior_change_observations
                            (
                                user,
                                change_type,
                                change_value,
                                status,
                                first_seen,
                                last_seen,
                                seen_count,
                                max_risk_score,
                                risky_context_count,
                                decision_reason,
                                manual_override,
                                manual_note,
                                decided_at
                            )
                            VALUES
                            (
                                :user,
                                :change_type,
                                :change_value,
                                'ACCEPTED',
                                :now,
                                :now,
                                3,
                                0,
                                0,
                                :reason,
                                1,
                                :note,
                                :now
                            )
                        """),
                        {
                            "user": target_user,
                            "change_type": change_type,
                            "change_value": change_value,
                            "now": whitelist_now,
                            "note": "발표용 정상 Baseline 행동",
                            "reason": (
                                "SOC 관리자 수동 승인: "
                                "발표용 정상 Baseline 행동"
                            ),
                        },
                    )

            db.commit()

        # -----------------------------------------
        # 8. 발표용 정상 Baseline 재구성
        #
        # 최근 10개 평일 x 하루 12건 = 총 120건
        #
        # 정상 업무 패턴:
        # - 월~금
        # - 09:00~17:00
        # - 정상 로그인
        # - Chrome / VS Code / Notepad
        # - Word / Excel / Outlook / PDF Reader
        # - 일반 문서 접근
        #
        # 의도적으로 제외:
        # - PowerShell
        # - USB
        #
        # 따라서 공격 시연에서 PowerShell / USB가
        # 기존 정상 행동과 명확하게 대비된다.
        # -----------------------------------------

        old_baseline_ids = [
            int(row[0])
            for row in db.execute(
                text("""
                    SELECT id
                    FROM security_events
                    WHERE user=:user
                      AND source=:baseline_source
                """),
                {
                    "user": target_user,
                    "baseline_source": baseline_source,
                },
            ).all()
        ]

        # 기존 발표용 Baseline의 Event Context 제거
        if old_baseline_ids and table_exists("event_context"):
            marks = ",".join(
                f":baseline_event_{i}"
                for i in range(len(old_baseline_ids))
            )

            params = {
                f"baseline_event_{i}": event_id
                for i, event_id in enumerate(old_baseline_ids)
            }

            db.execute(
                text(
                    "DELETE FROM event_context "
                    f"WHERE event_id IN ({marks})"
                ),
                params,
            )

        # 기존 presentation_baseline만 삭제
        db.execute(
            text("""
                DELETE FROM security_events
                WHERE user=:user
                  AND source=:baseline_source
            """),
            {
                "user": target_user,
                "baseline_source": baseline_source,
            },
        )

        db.commit()

        # -----------------------------------------
        # 최근 10개 평일 계산
        # -----------------------------------------

        now = datetime.now()

        business_days = []
        cursor = (
            now - timedelta(days=1)
        ).replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

        while len(business_days) < 10:
            if cursor.weekday() < 5:
                business_days.append(cursor)

            cursor -= timedelta(days=1)

        business_days = sorted(
            business_days
        )

        # -----------------------------------------
        # 하루 정상 행동 시나리오
        #
        # 12건 / 일
        # -----------------------------------------

        daily_template = [
            # 시간, 분, 이벤트 종류, 프로세스, 파일, 접근량
            (9,  0,  "login",   None,          None,                  0),

            (9, 15,  "process", "outlook.exe", None,                  0),
            (9, 40,  "process", "chrome.exe",  None,                  0),

            (10, 20, "file",    "winword.exe", "project_notes.docx", 2),

            (11,  0, "process", "code.exe",    None,                  0),
            (11, 40, "process", "notepad.exe", None,                  0),

            (13, 20, "file",    "excel.exe",   "weekly_report.xlsx", 3),

            (14, 10, "process", "chrome.exe",  None,                  0),
            (15,  0, "process", "acrord32.exe",None,                  0),

            (15, 40, "file",    "winword.exe", "meeting_notes.docx", 2),

            (16, 20, "process", "excel.exe",   None,                  0),
            (17,  0, "process", "outlook.exe", None,                  0),
        ]

        created_baseline = 0

        # 두 정상 IP를 충분히 반복시켜
        # 둘 다 알려진 Source IP가 되도록 한다.
        normal_ips = [
            "172.20.10.13",
            "127.0.0.1",
        ]

        for day_index, day in enumerate(business_days):

            for event_index, (
                hour,
                minute,
                event_kind,
                process_name,
                file_name,
                file_access_count,
            ) in enumerate(daily_template):

                event_time = day.replace(
                    hour=hour,
                    minute=minute,
                    second=0,
                    microsecond=0,
                )

                source_ip = normal_ips[
                    (day_index + event_index) % len(normal_ips)
                ]

                # ---------------------------------
                # 로그인 성공
                # ---------------------------------

                if event_kind == "login":
                    event_type = "login_success"
                    login_success = 1
                    process_value = None
                    file_value = None
                    grade_value = None
                    access_count = 0

                # ---------------------------------
                # 일반 파일 접근
                # ---------------------------------

                elif event_kind == "file":
                    event_type = "file_access"
                    login_success = 1
                    process_value = process_name
                    file_value = file_name
                    grade_value = "일반"
                    access_count = file_access_count

                # ---------------------------------
                # 정상 프로세스 실행
                # ---------------------------------

                else:
                    event_type = "process_execution"
                    login_success = None
                    process_value = process_name
                    file_value = None
                    grade_value = None
                    access_count = 0

                baseline_event = SecurityEvent(
                    user=target_user,
                    event_type=event_type,
                    timestamp=event_time,

                    host="DESKTOP-RIG50RH",
                    source=baseline_source,

                    raw_event_id=(
                        f"PRESENTATION-BASELINE-"
                        f"{day_index + 1:02d}-"
                        f"{event_index + 1:02d}"
                    ),

                    source_ip=source_ip,

                    login_success=login_success,
                    login_fail_count=0,

                    file_name=file_value,
                    file_path=(
                        f"C:\\WORK\\{file_value}"
                        if file_value
                        else None
                    ),
                    file_grade=grade_value,
                    file_access_count=access_count,

                    usb_connected=0,
                    device_name=None,
                    device_id=None,

                    process_name=process_value,

                    anomaly_score=0,
                    risk_score=5,
                    risk_level="LOW",

                    reasons=(
                        "발표용 IT 사용자 정상 업무 Baseline"
                    ),
                )

                db.add(baseline_event)
                db.flush()

                # ---------------------------------
                # Extended Context 정상 이력
                # ---------------------------------

                if table_exists("event_context"):
                    db.execute(
                        text("""
                            INSERT OR REPLACE INTO event_context
                            (
                                event_id,
                                user,
                                timestamp,
                                source_ip,
                                network_prefix,
                                workstation_name,
                                host,
                                logon_type,
                                command_line,
                                parent_process,
                                is_normal
                            )
                            VALUES
                            (
                                :event_id,
                                :user,
                                :timestamp,
                                :source_ip,
                                :network_prefix,
                                :workstation_name,
                                :host,
                                :logon_type,
                                :command_line,
                                :parent_process,
                                1
                            )
                        """),
                        {
                            "event_id": baseline_event.id,
                            "user": target_user,
                            "timestamp": event_time,
                            "source_ip": source_ip,

                            "network_prefix": (
                                "172.20.10.0/24"
                                if source_ip.startswith("172.20.10.")
                                else "127.0.0.0/24"
                            ),

                            "workstation_name": (
                                "DESKTOP-RIG50RH"
                            ),

                            "host": (
                                "DESKTOP-RIG50RH"
                            ),

                            "logon_type": "2",

                            "command_line": (
                                process_value
                                if process_value
                                else ""
                            ),

                            "parent_process": (
                                "explorer.exe"
                            ),
                        },
                    )

                created_baseline += 1

        db.commit()

        final_baseline_count = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.user == target_user,
                SecurityEvent.source == baseline_source,
                SecurityEvent.risk_level == "LOW",
            )
            .count()
        )

        return {
            "message": "siem_demo 발표 시나리오 초기화 완료",
            "user": target_user,
            "deleted": deleted,
            "behavior_change_preserved": True,
            "endpoint_learning_preserved": True,
            "baseline_preserved": True,
            "baseline_created": created_baseline,
            "baseline_event_count": final_baseline_count,
        }

    except Exception as error:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "시연 데이터 초기화 실패: "
                f"{type(error).__name__}: {error}"
            )
        )


# -------------------------------------------------
# Incident Correlation / Attack Storyline
# -------------------------------------------------

@app.get("/incidents")
def list_security_incidents(
    user: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    return get_incidents(
        db=db,
        user=user,
        status=status
    )


@app.get("/incidents/{incident_id}")
def read_security_incident(
    incident_id: int,
    db: Session = Depends(get_db)
):
    incident = get_incident(
        db=db,
        incident_id=incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="보안 사고를 찾을 수 없습니다."
        )

    return incident


@app.post("/incidents/{incident_id}/status")
def change_security_incident_status(
    incident_id: int,
    body: IncidentStatusUpdate,
    db: Session = Depends(get_db)
):
    incident, error = update_incident_status(
        db=db,
        incident_id=incident_id,
        status=body.status
    )

    if error:
        raise HTTPException(
            status_code=400,
            detail=error
        )

    return {
        "message": "보안 사고 상태가 변경되었습니다.",
        "incident": incident
    }


# -------------------------------------------------
# Response Playbook / SOAR-lite
# -------------------------------------------------

@app.get("/incidents/{incident_id}/playbook")
def read_incident_playbook(
    incident_id: int,
    db: Session = Depends(get_db)
):
    playbook, error = get_or_create_playbook(
        db=db,
        incident_id=incident_id
    )

    if error:
        raise HTTPException(
            status_code=404,
            detail=error
        )

    return playbook


@app.post(
    "/incidents/{incident_id}/playbook/steps/{step_id}"
)
def change_incident_playbook_step(
    incident_id: int,
    step_id: str,
    body: PlaybookStepUpdate,
    db: Session = Depends(get_db)
):
    result, error = update_playbook_step(
        db=db,
        incident_id=incident_id,
        step_id=step_id,
        action=body.action,
        note=body.note
    )

    if error:
        raise HTTPException(
            status_code=400,
            detail=error
        )

    return {
        "message": "Playbook 단계가 변경되었습니다.",
        "playbook": result
    }


# -------------------------------------------------
# Behavior Change Verification
# -------------------------------------------------

@app.get("/behavior-changes")
def list_behavior_changes(
    user: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    return get_behavior_changes(
        db=db,
        user=user,
        status=status
    )


@app.post("/behavior-changes/{observation_id}/decision")
def decide_behavior_change(
    observation_id: int,
    body: BehaviorChangeDecision,
    db: Session = Depends(get_db)
):
    result, error = update_behavior_change_decision(
        db=db,
        observation_id=observation_id,
        action=body.action,
        note=body.note
    )

    if error:
        raise HTTPException(
            status_code=400,
            detail=error
        )

    return {
        "message": "행동 변화에 대한 관리자 판정이 적용되었습니다.",
        "behavior_change": result
    }


# -------------------------------------------------
# Adaptive Personal UEBA 사용자 행동 프로필
# -------------------------------------------------

@app.get("/users/{user}/behavior-profile")
def get_behavior_profile(
    user: str,
    db: Session = Depends(get_db)
):
    profile = get_user_behavior_profile(
        db=db,
        user=user
    )

    return profile


# -------------------------------------------------
# Peer Group UEBA 프로필
# -------------------------------------------------

@app.get("/users/{user}/peer-profile")
def get_peer_profile(
    user: str,
    db: Session = Depends(get_db)
):
    monitored_user = (
        db.query(MonitoredUser)
        .filter(MonitoredUser.username == user)
        .first()
    )

    if not monitored_user:
        raise HTTPException(
            status_code=404,
            detail="등록된 사용자를 찾을 수 없습니다."
        )

    return get_peer_group_profile(
        db=db,
        user=user
    )


@app.post("/analyze-document")
async def analyze_document_api(
    file: UploadFile = File(...)
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="파일 이름이 없습니다."
        )

    if not file.filename.lower().endswith(
        ".docx"
    ):
        raise HTTPException(
            status_code=400,
            detail="현재는 DOCX 파일만 분석할 수 있습니다."
        )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".docx"
        ) as temp_file:

            shutil.copyfileobj(
                file.file,
                temp_file
            )

            temp_path = temp_file.name

        result = analyze_document(
            temp_path
        )

        return {
            "file_name": file.filename,
            "pii_score": result[
                "pii_score"
            ],
            "file_grade": result[
                "file_grade"
            ],
            "reasons": result[
                "reasons"
            ],
            "detected": result[
                "detected"
            ]
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"문서 분석 실패: "
                f"{str(error)}"
            )
        )

    finally:
        await file.close()

        if (
            temp_path
            and os.path.exists(temp_path)
        ):
            os.remove(temp_path)


@app.post("/analyze-file-access")
async def analyze_file_access(
    user: str = Form(...),
    source_ip: str = Form(...),
    file_access_count: int = Form(1),
    process_name: str = Form(
        "WINWORD.EXE"
    ),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="파일 이름이 없습니다."
        )

    if not file.filename.lower().endswith(
        ".docx"
    ):
        raise HTTPException(
            status_code=400,
            detail="현재는 DOCX 파일만 분석할 수 있습니다."
        )

    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".docx"
        ) as temp_file:

            shutil.copyfileobj(
                file.file,
                temp_file
            )

            temp_path = temp_file.name

        document_result = (
            analyze_document(
                temp_path
            )
        )

        security_event = EventCreate(
            user=user,
            event_type="file_access",
            source_ip=source_ip,
            login_success=1,
            file_name=file.filename,
            file_grade=document_result[
                "file_grade"
            ],
            file_access_count=(
                file_access_count
            ),
            process_name=process_name
        )

        security_result = (
            process_security_event(
                security_event,
                db
            )
        )

        return {
            "message": (
                "Document and file access "
                "analyzed"
            ),

            "document_analysis": {
                "file_name": (
                    file.filename
                ),
                "pii_score": (
                    document_result[
                        "pii_score"
                    ]
                ),
                "file_grade": (
                    document_result[
                        "file_grade"
                    ]
                ),
                "pii_reasons": (
                    document_result[
                        "reasons"
                    ]
                ),
                "detected": (
                    document_result[
                        "detected"
                    ]
                )
            },

            "security_analysis": (
                security_result
            )
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"파일 접근 분석 실패: "
                f"{str(error)}"
            )
        )

    finally:
        await file.close()

        if (
            temp_path
            and os.path.exists(temp_path)
        ):
            os.remove(temp_path)


@app.get("/events")
def get_events(
    limit: int = 500,
    db: Session = Depends(get_db)
):
    safe_limit = max(1, min(int(limit or 500), 5000))

    events = (
        db.query(SecurityEvent)
        .order_by(
            SecurityEvent.id.desc()
        )
        .limit(safe_limit)
        .all()
    )

    return events


@app.get("/events/{event_id}/endpoint-context")
def read_endpoint_event_context(
    event_id: int,
    db: Session = Depends(get_db)
):
    result = get_endpoint_event_context(db=db, event_id=event_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Endpoint Context를 찾을 수 없습니다.")
    return result


@app.get("/users/{user}/endpoint-profile")
def read_endpoint_profile(
    user: str,
    db: Session = Depends(get_db)
):
    return get_endpoint_profile(db=db, user=user)


@app.get("/events/{event_id}/risk-explanation")
def read_event_risk_explanation(
    event_id: int,
    db: Session = Depends(get_db)
):
    result = get_risk_explanation(
        db=db,
        event_id=event_id
    )

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="이벤트를 찾을 수 없습니다."
        )

    return result


# -------------------------------------------------
# 모니터링 사용자 관리
# -------------------------------------------------

@app.post("/users")
def create_monitored_user(user: MonitoredUserCreate, db: Session = Depends(get_db)):
    username = user.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="사용자 계정명을 입력해야 합니다.")

    existing_user = db.query(MonitoredUser).filter(
        MonitoredUser.username == username
    ).first()

    if existing_user:
        raise HTTPException(status_code=409, detail="이미 등록된 사용자입니다.")

    monitored_user = MonitoredUser(
        username=username,
        display_name=user.display_name,
        department=user.department,
        role=user.role,
        monitoring_enabled=1
    )
    db.add(monitored_user)
    db.commit()
    db.refresh(monitored_user)

    return {
        "message": "모니터링 사용자가 등록되었습니다.",
        "user": {
            "id": monitored_user.id,
            "username": monitored_user.username,
            "display_name": monitored_user.display_name,
            "department": monitored_user.department,
            "role": monitored_user.role,
            "monitoring_enabled": bool(monitored_user.monitoring_enabled),
            "created_at": monitored_user.created_at
        }
    }


@app.get("/users")
def get_monitored_users(db: Session = Depends(get_db)):
    users = db.query(MonitoredUser).order_by(MonitoredUser.id.asc()).all()
    results = []

    for monitored_user in users:
        profile = get_user_behavior_profile(
            db=db,
            user=monitored_user.username
        )
        results.append({
            "id": monitored_user.id,
            "username": monitored_user.username,
            "display_name": monitored_user.display_name,
            "department": monitored_user.department,
            "role": monitored_user.role,
            "monitoring_enabled": bool(monitored_user.monitoring_enabled),
            "created_at": monitored_user.created_at,
            "learning_status": profile["confidence_level"],
            "learning_event_count": profile["event_count"],
            "confidence_weight": profile["confidence_weight"]
        })

    return results


@app.get("/users/{username}")
def get_monitored_user(username: str, db: Session = Depends(get_db)):
    monitored_user = db.query(MonitoredUser).filter(
        MonitoredUser.username == username
    ).first()

    if not monitored_user:
        raise HTTPException(status_code=404, detail="등록된 사용자를 찾을 수 없습니다.")

    profile = get_user_behavior_profile(db=db, user=username)

    return {
        "id": monitored_user.id,
        "username": monitored_user.username,
        "display_name": monitored_user.display_name,
        "department": monitored_user.department,
        "role": monitored_user.role,
        "monitoring_enabled": bool(monitored_user.monitoring_enabled),
        "created_at": monitored_user.created_at,
        "behavior_profile": profile
    }


@app.post("/users/{username}/enable")
def enable_user_monitoring(username: str, db: Session = Depends(get_db)):
    monitored_user = db.query(MonitoredUser).filter(
        MonitoredUser.username == username
    ).first()

    if not monitored_user:
        raise HTTPException(status_code=404, detail="등록된 사용자를 찾을 수 없습니다.")

    monitored_user.monitoring_enabled = 1
    db.commit()
    db.refresh(monitored_user)

    return {
        "message": "사용자 모니터링이 활성화되었습니다.",
        "username": monitored_user.username,
        "monitoring_enabled": True
    }


@app.post("/users/{username}/disable")
def disable_user_monitoring(username: str, db: Session = Depends(get_db)):
    monitored_user = db.query(MonitoredUser).filter(
        MonitoredUser.username == username
    ).first()

    if not monitored_user:
        raise HTTPException(status_code=404, detail="등록된 사용자를 찾을 수 없습니다.")

    monitored_user.monitoring_enabled = 0
    db.commit()
    db.refresh(monitored_user)

    return {
        "message": "사용자 모니터링이 중지되었습니다.",
        "username": monitored_user.username,
        "monitoring_enabled": False
    }


@app.delete("/users/{username}")
def delete_monitored_user(username: str, db: Session = Depends(get_db)):
    monitored_user = db.query(MonitoredUser).filter(
        MonitoredUser.username == username
    ).first()

    if not monitored_user:
        raise HTTPException(status_code=404, detail="등록된 사용자를 찾을 수 없습니다.")

    db.delete(monitored_user)
    db.commit()

    return {
        "message": "모니터링 대상에서 사용자가 삭제되었습니다.",
        "username": username,
        "security_events_preserved": True
    }


# -------------------------------------------------
# Adaptive UEBA 기준선 학습용 시연 데이터
# -------------------------------------------------


@app.get("/users/{user}/dynamic-risk")
def get_user_dynamic_risk(
    user: str,
    db: Session = Depends(get_db)
):
    monitored_user = (
        db.query(MonitoredUser)
        .filter(
            MonitoredUser.username == user
        )
        .first()
    )

    if monitored_user is None:
        raise HTTPException(
            status_code=404,
            detail=f"등록되지 않은 모니터링 사용자입니다: {user}"
        )

    return get_dynamic_user_risk_profile(
        db=db,
        user=user
    )


@app.post("/demo/train-baseline")
def train_adaptive_baseline_demo(
    db: Session = Depends(get_db)
):
    from datetime import timedelta

    # 실제/기존 시연 사용자와 분리된
    # Adaptive UEBA 전용 사용자
    demo_users = [
        "office_demo",
        "flex_demo"
    ]

    # --------------------------------
    # Adaptive UEBA 전용 사용자 데이터 초기화
    #
    # office_demo / flex_demo는 이 기능에서만
    # 사용하는 전용 계정이므로 기존 데이터를
    # 모두 지워도 다른 시연 데이터에 영향 없음
    # --------------------------------

    db.query(SecurityEvent).filter(
        SecurityEvent.user.in_(demo_users)
    ).delete(
        synchronize_session=False
    )

    db.commit()

    now = datetime.now()

    office_count = 0
    flex_count = 0

    office_behavior_index = 0
    flex_behavior_index = 0

    # --------------------------------
    # office_demo
    #
    # 일반적인 주간 사무직 사용자
    # 월~금
    # 09:00~17:00
    # Word / Excel
    # IP: 192.168.56.101
    # 파일 접근량: 평균 3
    # USB: 사용하지 않음
    # --------------------------------

    for days_ago in range(1, 21):
        target_date = (
            now - timedelta(days=days_ago)
        )

        if target_date.weekday() >= 5:
            continue

        for hour in [
            9,
            10,
            11,
            13,
            14,
            15,
            16,
            17
        ]:
            timestamp = target_date.replace(
                hour=hour,
                minute=0,
                second=0,
                microsecond=0
            )

            process_name = (
                "WINWORD.EXE"
                if office_behavior_index % 2 == 0
                else "EXCEL.EXE"
            )

            # 정상 파일 접근 행동
            file_event = SecurityEvent(
                user="office_demo",
                event_type="file_access",
                timestamp=timestamp,
                source_ip="192.168.56.101",
                login_success=1,
                login_fail_count=0,
                file_name="normal_office_document.docx",
                file_grade="일반",
                file_access_count=3,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons=(
                    "Adaptive Baseline 학습 데이터 "
                    "- office_demo file"
                )
            )

            db.add(file_event)

            # 정상 프로세스 실행 행동
            process_event = SecurityEvent(
                user="office_demo",
                event_type="process_execution",
                timestamp=(
                    timestamp
                    + timedelta(minutes=1)
                ),
                source_ip="192.168.56.101",
                login_success=1,
                login_fail_count=0,
                file_name=None,
                file_grade=None,
                file_access_count=0,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons=(
                    "Adaptive Baseline 학습 데이터 "
                    "- office_demo process"
                )
            )

            db.add(process_event)

            office_count += 2
            office_behavior_index += 1

    # --------------------------------
    # flex_demo
    #
    # 재택 / 유연근무 IT 사용자
    # 평일 저녁~다음날 새벽
    # 18:00~02:00
    # PowerShell / VS Code
    # IP: 192.168.56.102
    # 파일 접근량: 평균 5
    # USB: 사용하지 않음
    # --------------------------------

    for days_ago in range(1, 21):
        target_date = (
            now - timedelta(days=days_ago)
        )

        if target_date.weekday() >= 5:
            continue

        # --------------------------------
        # 당일 18:00~23:00
        # --------------------------------

        for hour in [
            18,
            19,
            20,
            21,
            22,
            23
        ]:
            timestamp = target_date.replace(
                hour=hour,
                minute=0,
                second=0,
                microsecond=0
            )

            process_name = (
                "powershell.exe"
                if flex_behavior_index % 2 == 0
                else "Code.exe"
            )

            file_event = SecurityEvent(
                user="flex_demo",
                event_type="file_access",
                timestamp=timestamp,
                source_ip="192.168.56.102",
                login_success=1,
                login_fail_count=0,
                file_name="development_file.txt",
                file_grade="일반",
                file_access_count=5,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons=(
                    "Adaptive Baseline 학습 데이터 "
                    "- flex_demo file"
                )
            )

            db.add(file_event)

            process_event = SecurityEvent(
                user="flex_demo",
                event_type="process_execution",
                timestamp=(
                    timestamp
                    + timedelta(minutes=1)
                ),
                source_ip="192.168.56.102",
                login_success=1,
                login_fail_count=0,
                file_name=None,
                file_grade=None,
                file_access_count=0,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons=(
                    "Adaptive Baseline 학습 데이터 "
                    "- flex_demo process"
                )
            )

            db.add(process_event)

            flex_count += 2
            flex_behavior_index += 1

        # --------------------------------
        # 다음날 00:00~02:00
        #
        # 금요일 저녁 작업의 경우 토요일 새벽까지
        # 이어지는 것이 정상적인 유연근무 패턴으로
        # 학습될 수 있음
        # --------------------------------

        next_date = (
            target_date
            + timedelta(days=1)
        )

        for hour in [
            0,
            1,
            2
        ]:
            timestamp = next_date.replace(
                hour=hour,
                minute=0,
                second=0,
                microsecond=0
            )

            process_name = (
                "powershell.exe"
                if flex_behavior_index % 2 == 0
                else "Code.exe"
            )

            file_event = SecurityEvent(
                user="flex_demo",
                event_type="file_access",
                timestamp=timestamp,
                source_ip="192.168.56.102",
                login_success=1,
                login_fail_count=0,
                file_name="development_file.txt",
                file_grade="일반",
                file_access_count=5,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons=(
                    "Adaptive Baseline 학습 데이터 "
                    "- flex_demo file"
                )
            )

            db.add(file_event)

            process_event = SecurityEvent(
                user="flex_demo",
                event_type="process_execution",
                timestamp=(
                    timestamp
                    + timedelta(minutes=1)
                ),
                source_ip="192.168.56.102",
                login_success=1,
                login_fail_count=0,
                file_name=None,
                file_grade=None,
                file_access_count=0,
                usb_connected=0,
                process_name=process_name,
                anomaly_score=0,
                risk_score=0,
                risk_level="LOW",
                reasons=(
                    "Adaptive Baseline 학습 데이터 "
                    "- flex_demo process"
                )
            )

            db.add(process_event)

            flex_count += 2
            flex_behavior_index += 1

    db.commit()

    # --------------------------------
    # 학습된 개인 행동 프로필 확인
    # --------------------------------

    office_profile = (
        get_user_behavior_profile(
            db=db,
            user="office_demo"
        )
    )

    flex_profile = (
        get_user_behavior_profile(
            db=db,
            user="flex_demo"
        )
    )

    return {
        "message": (
            "Adaptive UEBA baseline "
            "training completed"
        ),

        "office_demo": {
            "description": (
                "일반 주간 사무직 사용자"
            ),
            "created_events": (
                office_count
            ),
            "profile": (
                office_profile
            )
        },

        "flex_demo": {
            "description": (
                "재택/유연근무 IT 사용자"
            ),
            "created_events": (
                flex_count
            ),
            "profile": (
                flex_profile
            )
        }
    }

# -------------------------------------------------
# Adaptive UEBA 개인별 기준선 비교 시연
# -------------------------------------------------

@app.post("/demo/compare-adaptive-baseline")
def compare_adaptive_baseline_demo(
    db: Session = Depends(get_db)
):
    # 동일 행동 조건
    test_hour = 23
    test_process = "powershell.exe"
    test_file_access_count = 5
    test_usb_connected = 0

    # 고정 Rule에서 23시는 "비정상 시간대 접근"으로 판단된다.
    # 이 데모에서는 동일한 Rule 증거를 두 사용자에게 똑같이 적용한다.
    demo_rule_reasons = [
        "비정상 시간대 접근"
    ]

    # office_demo 개인 기준선 분석
    office_score, office_reasons = (
        analyze_user_baseline(
            db=db,
            user="office_demo",
            current_ip="192.168.56.101",
            current_hour=test_hour,
            current_file_access_count=(
                test_file_access_count
            ),
            current_process_name=(
                test_process
            ),
            current_usb_connected=(
                test_usb_connected
            ),
            current_timestamp=None
        )
    )

    # flex_demo 개인 기준선 분석
    flex_score, flex_reasons = (
        analyze_user_baseline(
            db=db,
            user="flex_demo",
            current_ip="192.168.56.102",
            current_hour=test_hour,
            current_file_access_count=(
                test_file_access_count
            ),
            current_process_name=(
                test_process
            ),
            current_usb_connected=(
                test_usb_connected
            ),
            current_timestamp=None
        )
    )

    # 동일한 23시 행동에 대해 Adaptive Compensation 비교
    office_adaptive = (
        calculate_adaptive_compensation(
            db=db,
            user="office_demo",
            current_hour=test_hour,
            current_process_name=test_process,
            current_timestamp=None,
            rule_reasons=demo_rule_reasons,
            baseline_score=office_score,
            sequence_score=0,
            event_type="process_execution",
            file_grade=None,
            file_access_count=0,
            usb_connected=0,
            login_fail_count=0
        )
    )

    flex_adaptive = (
        calculate_adaptive_compensation(
            db=db,
            user="flex_demo",
            current_hour=test_hour,
            current_process_name=test_process,
            current_timestamp=None,
            rule_reasons=demo_rule_reasons,
            baseline_score=flex_score,
            sequence_score=0,
            event_type="process_execution",
            file_grade=None,
            file_access_count=0,
            usb_connected=0,
            login_fail_count=0
        )
    )

    office_compensation = float(
        office_adaptive.get("score", 0) or 0
    )

    flex_compensation = float(
        flex_adaptive.get("score", 0) or 0
    )

    if office_score == 0:
        office_judgment = "개인 정상 패턴"
    else:
        office_judgment = "개인 기준선 이탈"

    if flex_score == 0:
        flex_judgment = "개인 정상 패턴"
    else:
        flex_judgment = "개인 기준선 이탈"

    return {
        "message": (
            "동일 행동에 대한 개인별 Adaptive UEBA "
            "및 위험 보정 비교 완료"
        ),

        "same_behavior": {
            "hour": test_hour,
            "process_name": test_process,
            "file_access_count": (
                test_file_access_count
            ),
            "usb_connected": (
                test_usb_connected
            ),
            "fixed_rule_reason": (
                "비정상 시간대 접근"
            )
        },

        "office_demo": {
            "user_type": (
                "일반 주간 사무직 사용자"
            ),
            "normal_behavior": {
                "active_hours": "09:00~17:00",
                "normal_processes": [
                    "winword.exe",
                    "excel.exe"
                ]
            },
            "baseline_score": office_score,
            "judgment": office_judgment,
            "baseline_reasons": office_reasons,
            "adaptive_compensation": (
                office_compensation
            ),
            "adaptive_applied": bool(
                office_adaptive.get(
                    "applied",
                    False
                )
            ),
            "confidence_level": (
                office_adaptive.get(
                    "confidence_level"
                )
            ),
            "confidence_weight": (
                office_adaptive.get(
                    "confidence_weight"
                )
            ),
            "adaptive_reasons": (
                office_adaptive.get(
                    "reasons",
                    []
                )
            )
        },

        "flex_demo": {
            "user_type": (
                "재택/유연근무 IT 사용자"
            ),
            "normal_behavior": {
                "active_hours": "18:00~02:00",
                "normal_processes": [
                    "powershell.exe",
                    "code.exe"
                ]
            },
            "baseline_score": flex_score,
            "judgment": flex_judgment,
            "baseline_reasons": flex_reasons,
            "adaptive_compensation": (
                flex_compensation
            ),
            "adaptive_applied": bool(
                flex_adaptive.get(
                    "applied",
                    False
                )
            ),
            "confidence_level": (
                flex_adaptive.get(
                    "confidence_level"
                )
            ),
            "confidence_weight": (
                flex_adaptive.get(
                    "confidence_weight"
                )
            ),
            "adaptive_reasons": (
                flex_adaptive.get(
                    "reasons",
                    []
                )
            )
        },

        "comparison": {
            "office_demo": (
                "23시는 기존 근무시간에서 벗어나므로 "
                "개인 기준선 이탈로 판단하고 시간 규칙을 보정하지 않음"
            ),
            "flex_demo": (
                "23시는 충분히 학습된 유연근무 사용자의 "
                "정상 활동 시간대이므로 시간 규칙 기여도를 제한적으로 보정"
            ),
            "security_guard": (
                "대외비/내부 문서 접근, USB, 반복 로그인 실패, "
                "공격 시퀀스 등 보안 증거가 있으면 Adaptive 보정을 적용하지 않음"
            )
        }
    }




# -------------------------------------------------
# Peer Group UEBA 학습 시연
# -------------------------------------------------

@app.post("/demo/train-peer-group")
def train_peer_group_demo(
    db: Session = Depends(get_db)
):
    from datetime import timedelta

    peer_usernames = [
        "peer_dev01",
        "peer_dev02"
    ]

    # 기존 시연용 Peer 등록/이벤트만 정리한다.
    # 실제 사용자 김재경의 데이터에는 손대지 않는다.
    db.query(SecurityEvent).filter(
        SecurityEvent.user.in_(peer_usernames)
    ).delete(
        synchronize_session=False
    )

    db.query(MonitoredUser).filter(
        MonitoredUser.username.in_(peer_usernames)
    ).delete(
        synchronize_session=False
    )

    db.commit()

    now = datetime.now()

    # 김재경과 동일한 IT / Developer 그룹으로 등록
    # 등록 시점 Guard를 통과하도록 학습 이벤트는 등록 이후 시각으로 생성한다.
    peer_users = []

    for index, username in enumerate(
        peer_usernames,
        start=1
    ):
        monitored_user = MonitoredUser(
            username=username,
            display_name=f"Peer Developer {index:02d}",
            department="IT",
            role="Developer",
            monitoring_enabled=1,
            created_at=(
                now - timedelta(days=15)
            )
        )

        db.add(monitored_user)
        peer_users.append(monitored_user)

    db.commit()

    created_event_count = 0

    # IT Developer Peer 정상 패턴
    #
    # - 평일 09:00~18:00
    # - VS Code / PowerShell
    # - 파일 접근량 약 4~5
    # - USB 사용 없음
    # - 각 Peer 30개 이상의 LOW 이벤트 생성
    behavior_index = 0

    for days_ago in range(1, 11):
        target_date = (
            now - timedelta(days=days_ago)
        )

        if target_date.weekday() >= 5:
            continue

        for username_index, username in enumerate(
            peer_usernames
        ):
            source_ip = (
                f"192.168.56.{201 + username_index}"
            )

            for hour in [
                9,
                11,
                14,
                16,
                18
            ]:
                timestamp = target_date.replace(
                    hour=hour,
                    minute=0,
                    second=0,
                    microsecond=0
                )

                process_name = (
                    "Code.exe"
                    if behavior_index % 2 == 0
                    else "powershell.exe"
                )

                file_access_count = (
                    4
                    if behavior_index % 2 == 0
                    else 5
                )

                file_event = SecurityEvent(
                    user=username,
                    event_type="file_access",
                    timestamp=timestamp,
                    source_ip=source_ip,
                    login_success=1,
                    login_fail_count=0,
                    file_name="development_source.txt",
                    file_grade="일반",
                    file_access_count=file_access_count,
                    usb_connected=0,
                    process_name=process_name,
                    anomaly_score=0,
                    risk_score=0,
                    risk_level="LOW",
                    reasons=(
                        "Peer Group UEBA 정상 학습 데이터"
                    )
                )

                process_event = SecurityEvent(
                    user=username,
                    event_type="process_execution",
                    timestamp=(
                        timestamp
                        + timedelta(minutes=1)
                    ),
                    source_ip=source_ip,
                    login_success=1,
                    login_fail_count=0,
                    file_name=None,
                    file_grade=None,
                    file_access_count=0,
                    usb_connected=0,
                    process_name=process_name,
                    anomaly_score=0,
                    risk_score=0,
                    risk_level="LOW",
                    reasons=(
                        "Peer Group UEBA 정상 학습 데이터"
                    )
                )

                db.add(file_event)
                db.add(process_event)

                created_event_count += 2
                behavior_index += 1

    db.commit()

    # 실제 대상 사용자의 Peer Profile이 형성되었는지 확인
    target_profile = get_peer_group_profile(
        db=db,
        user="김재경"
    )

    return {
        "message": (
            "Peer Group UEBA training completed"
        ),
        "target_user": "김재경",
        "group_key": "IT / Developer",
        "created_peer_users": peer_usernames,
        "created_learning_events": (
            created_event_count
        ),
        "peer_profile": target_profile,
        "note": (
            "시연용 Peer 사용자는 실제 김재경 이벤트와 "
            "분리되어 있으며 LOW 정상 이벤트만 생성됨"
        )
    }


# -------------------------------------------------
# Peer Group UEBA 정상/이탈 행동 비교 시연
# -------------------------------------------------

@app.post("/demo/compare-peer-group")
def compare_peer_group_demo(
    db: Session = Depends(get_db)
):
    profile = get_peer_group_profile(
        db=db,
        user="김재경"
    )

    if not profile.get(
        "available",
        False
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Peer Group 기준선이 아직 준비되지 않았습니다. "
                "먼저 POST /demo/train-peer-group 을 실행하세요."
            )
        )

    now = datetime.now()

    # 동일 Peer Group을 기준으로 두 행동을 비교한다.
    #
    # 정상 행동:
    # 평일 업무시간 + Code.exe + 파일 접근 5 + USB 없음
    #
    # 이탈 행동:
    # 새벽 03시 + rar.exe + 파일 접근 30 + USB 연결
    #
    # current_timestamp의 날짜는 Peer의 정상 평일 패턴과
    # 비교가 가능하도록 최근 월요일로 맞춘다.
    days_since_monday = now.weekday()

    test_date = (
        now
        if days_since_monday == 0
        else now - __import__(
            "datetime"
        ).timedelta(
            days=days_since_monday
        )
    )

    normal_timestamp = test_date.replace(
        hour=14,
        minute=0,
        second=0,
        microsecond=0
    )

    abnormal_timestamp = test_date.replace(
        hour=3,
        minute=0,
        second=0,
        microsecond=0
    )

    normal_result = analyze_peer_group_baseline(
        db=db,
        user="김재경",
        current_ip="192.168.56.210",
        current_hour=14,
        current_file_access_count=5,
        current_process_name="Code.exe",
        current_usb_connected=0,
        current_timestamp=normal_timestamp
    )

    abnormal_result = analyze_peer_group_baseline(
        db=db,
        user="김재경",
        current_ip="192.168.56.250",
        current_hour=3,
        current_file_access_count=30,
        current_process_name="rar.exe",
        current_usb_connected=1,
        current_timestamp=abnormal_timestamp
    )

    return {
        "message": (
            "Peer Group UEBA behavior comparison completed"
        ),
        "target_user": "김재경",
        "group_key": profile.get(
            "group_key"
        ),
        "peer_profile": {
            "peer_user_count": profile.get(
                "peer_user_count"
            ),
            "peer_event_count": profile.get(
                "peer_event_count"
            ),
            "active_hours": profile.get(
                "active_hours"
            ),
            "normal_processes": profile.get(
                "normal_processes"
            ),
            "average_file_access": profile.get(
                "average_file_access"
            ),
            "usb_usage_rate_percent": profile.get(
                "usb_usage_rate_percent"
            )
        },
        "normal_behavior": {
            "behavior": (
                "14:00 / Code.exe / 파일 접근 5 / USB 없음"
            ),
            "peer_score": normal_result.get(
                "score",
                0
            ),
            "judgment": (
                "Peer Group 정상 범위"
                if normal_result.get("score", 0) == 0
                else "Peer Group 이탈"
            ),
            "reasons": normal_result.get(
                "reasons",
                []
            ),
            "peer_group_available": (
                normal_result.get(
                    "group_available",
                    False
                )
            )
        },
        "abnormal_behavior": {
            "behavior": (
                "03:00 / rar.exe / 파일 접근 30 / USB 연결"
            ),
            "peer_score": abnormal_result.get(
                "score",
                0
            ),
            "judgment": (
                "Peer Group 정상 범위"
                if abnormal_result.get("score", 0) == 0
                else "Peer Group 이탈"
            ),
            "reasons": abnormal_result.get(
                "reasons",
                []
            ),
            "peer_group_available": (
                abnormal_result.get(
                    "group_available",
                    False
                )
            )
        },
        "interpretation": (
            "개인 행동 이력이 부족한 사용자도 같은 IT / Developer "
            "동료 그룹의 정상 패턴을 보조 기준으로 비교할 수 있음"
        ),
        "risk_integration": (
            "충분한 Peer Group 기준선이 형성되고 파일 접근량/USB 등 "
            "강한 이탈 증거 또는 Peer Score 40 이상의 복합 이탈이 있을 때만 "
            "Peer Score의 20%를 최종 Risk Score에 보조 신호로 반영"
        )
    }


# -------------------------------------------------
# 시연 데이터 초기화
# -------------------------------------------------

@app.delete("/demo/reset")
def reset_demo_data(
    db: Session = Depends(get_db)
):
    deleted_count = (
        db.query(SecurityEvent)
        .delete()
    )

    db.commit()

    return {
        "message": "Demo data reset completed",
        "deleted_events": deleted_count
    }


# -------------------------------------------------
# 정상 사용자 시나리오
# -------------------------------------------------

@app.post("/demo/normal")
def run_normal_demo(
    db: Session = Depends(get_db)
):
    normal_events = [
        EventCreate(
            user="user01",
            event_type="login_success",
            source_ip="192.168.56.101",
            login_success=1
        ),

        EventCreate(
            user="user01",
            event_type="file_access",
            source_ip="192.168.56.101",
            login_success=1,
            file_name="meeting_notes.docx",
            file_grade="일반",
            file_access_count=3,
            process_name="WINWORD.EXE"
        ),

        EventCreate(
            user="user01",
            event_type="file_access",
            source_ip="192.168.56.101",
            login_success=1,
            file_name="schedule.xlsx",
            file_grade="일반",
            file_access_count=2,
            process_name="EXCEL.EXE"
        )
    ]

    results = []

    for event in normal_events:
        result = process_security_event(
            event,
            db
        )

        results.append(
            result
        )

    return {
        "message": "Normal scenario completed",
        "scenario": "NORMAL",
        "generated_events": len(results),
        "results": results
    }


# -------------------------------------------------
# 공격 사용자 시나리오
# -------------------------------------------------

@app.post("/demo/attack")
def run_attack_demo(
    db: Session = Depends(get_db)
):
    attack_events = []

    for fail_count in range(1, 6):
        attack_events.append(
            EventCreate(
                user="user02",
                event_type="login_failed",
                source_ip="203.0.113.50",
                login_success=0,
                login_fail_count=fail_count
            )
        )

    attack_events.append(
        EventCreate(
            user="user02",
            event_type="login_success",
            source_ip="203.0.113.50",
            login_success=1
        )
    )

    attack_events.append(
        EventCreate(
            user="user02",
            event_type="file_access",
            source_ip="203.0.113.50",
            login_success=1,
            file_name="customer_personal_data.docx",
            file_grade="대외비",
            file_access_count=35,
            process_name="WINWORD.EXE"
        )
    )

    attack_events.append(
        EventCreate(
            user="user02",
            event_type="usb_connected",
            source_ip="203.0.113.50",
            usb_connected=1
        )
    )

    attack_events.append(
        EventCreate(
            user="user02",
            event_type="process_execution",
            source_ip="203.0.113.50",
            process_name="chrome.exe"
        )
    )

    results = []

    for event in attack_events:
        result = process_security_event(
            event,
            db
        )

        results.append(
            result
        )

    final_result = results[-1]

    return {
        "message": "Attack scenario completed",
        "scenario": "ATTACK",
        "generated_events": len(results),

        "final_risk_score": (
            final_result[
                "risk_score"
            ]
        ),

        "final_risk_level": (
            final_result[
                "risk_level"
            ]
        ),

        "results": results
    }


# -------------------------------------------------
# Incident-aware AI SOC Analyst
# -------------------------------------------------

@app.post("/ai-analysis/incident/{incident_id}")
def analyze_incident_with_ai_api(
    incident_id: int,
    db: Session = Depends(get_db)
):
    incident = get_incident(
        db=db,
        incident_id=incident_id
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail="보안 사고를 찾을 수 없습니다."
        )

    event_ids = (
        incident.get("event_ids")
        or incident.get("related_event_ids")
        or []
    )

    storyline = incident.get("storyline") or []

    if not event_ids:
        event_ids = [
            step.get("event_id")
            for step in storyline
            if step.get("event_id") is not None
        ]

    normalized_event_ids = []

    for event_id in event_ids:
        try:
            normalized_event_ids.append(int(event_id))
        except (TypeError, ValueError):
            continue

    related_events = []

    if normalized_event_ids:
        related_events = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.id.in_(
                    normalized_event_ids
                )
            )
            .all()
        )

        order = {
            event_id: index
            for index, event_id in enumerate(
                normalized_event_ids
            )
        }

        related_events.sort(
            key=lambda item: order.get(
                item.id,
                999999
            )
        )

    dynamic_user_risk = None

    try:
        dynamic_user_risk = get_dynamic_user_risk_profile(
            db=db,
            user=incident.get("user")
        )
    except Exception:
        dynamic_user_risk = None

    try:
        ai_result = analyze_incident_with_ai(
            incident=incident,
            events=related_events,
            dynamic_user_risk=dynamic_user_risk
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Incident AI SOC 분석 실패: {str(error)}"
        )

    return {
        "incident_id": incident_id,
        "user": incident.get("user"),
        "severity": incident.get("severity"),
        "correlation_score": incident.get("correlation_score"),
        "related_event_count": len(related_events),
        "dynamic_user_risk": dynamic_user_risk,
        "ai_analysis": ai_result
    }


# -------------------------------------------------
# AI 보안 사고 분석
# -------------------------------------------------

@app.post("/ai-analysis/{event_id}")
def analyze_event_with_ai(
    event_id: int,
    db: Session = Depends(get_db)
):
    event = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.id == event_id
        )
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="해당 이벤트를 찾을 수 없습니다."
        )

    reasons = []

    if event.reasons:
        reasons = [
            reason.strip()
            for reason in event.reasons.split(",")
            if reason.strip()
        ]

    try:
        ai_result = analyze_security_incident(
            user=event.user,
            event_type=event.event_type,
            risk_score=event.risk_score,
            risk_level=event.risk_level,
            reasons=reasons,
            source_ip=event.source_ip,
            file_name=event.file_name,
            file_grade=event.file_grade,
            process_name=event.process_name
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"AI 보안 분석 실패: "
                f"{str(error)}"
            )
        )

    return {
        "event_id": event.id,
        "user": event.user,
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "ai_analysis": ai_result
    }

