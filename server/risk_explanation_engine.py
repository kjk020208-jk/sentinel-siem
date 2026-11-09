import json
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import Session

from server.database import Base
from server.models import SecurityEvent


class EventRiskExplanation(Base):
    __tablename__ = "event_risk_explanations"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(
        Integer,
        ForeignKey("security_events.id"),
        unique=True,
        index=True,
        nullable=False
    )
    explanation_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)


def _risk_level_korean(level):
    return {
        "LOW": "낮음",
        "MEDIUM": "주의",
        "HIGH": "높음",
        "CRITICAL": "매우 높음",
    }.get(str(level or "").upper(), str(level or "-"))


def _component_plain_text(key, contribution, source_score, guard_passed=None, applied=None):
    c = float(contribution or 0)
    s = float(source_score or 0)

    if key == "base":
        if c <= 0:
            return "규칙 및 ML에서 뚜렷한 위험 신호가 거의 발견되지 않았습니다."
        return f"규칙·ML 분석에서 위험 신호가 확인되어 {c:.2f}점이 반영됐습니다."

    if key == "personal_baseline":
        if c <= 0:
            return "현재 행동이 개인의 평소 행동과 크게 다르지 않았습니다."
        return (
            f"현재 행동이 개인의 평소 패턴과 달라 "
            f"원점수 {s:.2f}의 30%인 {c:.2f}점이 추가됐습니다."
        )

    if key == "sequence":
        if c <= 0:
            return "앞뒤 이벤트가 다단계 공격 흐름으로 강하게 연결되지는 않았습니다."
        return (
            f"앞뒤 이벤트가 공격 흐름으로 연결되어 "
            f"원점수 {s:.2f}의 40%인 {c:.2f}점이 추가됐습니다."
        )

    if key == "peer_group":
        if not guard_passed:
            return "동료 그룹과 차이는 있었더라도 신뢰 조건을 통과하지 못해 최종 점수에는 반영하지 않았습니다."
        if c <= 0:
            return "동료 그룹 대비 의미 있는 추가 위험은 없었습니다."
        return f"같은 역할의 동료와 비교해 이례적인 행동이어서 {c:.2f}점이 추가됐습니다."

    if key == "adaptive":
        if applied and c < 0:
            return f"충분히 학습된 개인 정상 패턴과 일치해 위험도를 {abs(c):.2f}점 낮췄습니다."
        return "정상 패턴으로 확신할 수 없어 위험도 감점은 적용하지 않았습니다."

    return "위험도 계산 구성요소입니다."


def _receipt_line(label, contribution):
    c = float(contribution or 0)
    sign = "+" if c > 0 else ""
    return f"{label}: {sign}{c:.2f}점"


def _build_summary(final_score, risk_level, components, floor_applied, floor_reason):
    active_positive = [
        item for item in components
        if float(item.get("contribution", 0) or 0) > 0
    ]
    active_positive.sort(
        key=lambda x: float(x.get("contribution", 0) or 0),
        reverse=True
    )

    top_labels = [item["label"] for item in active_positive[:2]]

    if top_labels:
        factor_text = ", ".join(top_labels)
        core = f"주요 상승 요인은 {factor_text}입니다."
    else:
        core = "뚜렷한 위험 상승 요인은 확인되지 않았습니다."

    floor_text = ""
    if floor_applied:
        floor_text = f" 추가 안전장치가 적용되어 최종 점수가 보정됐습니다 ({floor_reason})."

    return (
        f"최종 위험점수는 {float(final_score or 0):.2f}점이며 "
        f"위험 등급은 {_risk_level_korean(risk_level)}입니다. "
        f"{core}{floor_text}"
    )


def _build_decision_text(final_score, risk_level):
    score = float(final_score or 0)
    level = str(risk_level or "").upper()

    if level == "CRITICAL":
        return "즉시 조사와 대응이 필요한 매우 높은 위험 이벤트입니다."
    if level == "HIGH":
        return "우선순위를 높여 관련 사용자와 연관 이벤트를 조사해야 합니다."
    if level == "MEDIUM":
        return "정상 행동으로 단정하지 말고 추가 맥락과 연속 행동을 확인해야 합니다."
    return "현재 단일 이벤트 기준 위험은 낮지만, 이후 연속 행동과 행동 변화 상태는 계속 관찰합니다."


def build_risk_explanation(
    *,
    event_id,
    rule_score,
    anomaly_score,
    base_score,
    baseline_score,
    sequence_score,
    peer_score,
    peer_contribution,
    peer_risk_guard_passed,
    adaptive_compensation,
    adaptive_applied,
    adaptive_confidence_level,
    score_before_floor,
    final_score,
    risk_level,
    floor_applied,
    floor_reason,
    reasons
):
    baseline_contribution = round(float(baseline_score or 0) * 0.3, 2)
    sequence_contribution = round(float(sequence_score or 0) * 0.4, 2)

    raw_components = [
        {
            "key": "base",
            "label": "규칙 + ML 기본 위험",
            "source_score": round(float(base_score or 0), 2),
            "weight": None,
            "contribution": round(float(base_score or 0), 2),
            "direction": "increase",
            "description": (
                f"Rule Score {float(rule_score or 0):.2f}, "
                f"Anomaly Score {float(anomaly_score or 0):.2f}를 "
                "Risk Engine으로 결합한 기본 위험도"
            )
        },
        {
            "key": "personal_baseline",
            "label": "개인 행동 기준선 이탈",
            "source_score": round(float(baseline_score or 0), 2),
            "weight": 0.3,
            "contribution": baseline_contribution,
            "direction": "increase",
            "description": "개인별 정상 행동과 현재 이벤트의 이탈 정도"
        },
        {
            "key": "sequence",
            "label": "공격 시퀀스",
            "source_score": round(float(sequence_score or 0), 2),
            "weight": 0.4,
            "contribution": sequence_contribution,
            "direction": "increase",
            "description": "시간 순서가 있는 다단계 공격 행동의 연결 정도"
        },
        {
            "key": "peer_group",
            "label": "동료 그룹 비교",
            "source_score": round(float(peer_score or 0), 2),
            "weight": 0.2,
            "contribution": round(float(peer_contribution or 0), 2),
            "direction": "increase",
            "guard_passed": bool(peer_risk_guard_passed),
            "description": (
                "Peer Risk Guard를 통과한 동료 그룹 이탈 신호만 반영"
                if peer_risk_guard_passed
                else "동료와 차이는 있었지만 신뢰 조건을 통과하지 못해 최종 점수에는 미반영"
            )
        },
        {
            "key": "adaptive",
            "label": "정상 패턴 보정",
            "source_score": round(float(adaptive_compensation or 0), 2),
            "weight": None,
            "contribution": -round(float(adaptive_compensation or 0), 2),
            "direction": "decrease",
            "applied": bool(adaptive_applied),
            "confidence_level": adaptive_confidence_level,
            "description": (
                "충분히 학습된 개인 정상 패턴과 일치하여 제한적으로 위험도를 보정"
                if adaptive_applied
                else "보정 조건을 충족하지 않아 위험도 감소 없음"
            )
        }
    ]

    components = []
    for item in raw_components:
        item = dict(item)
        item["plain_explanation"] = _component_plain_text(
            item["key"],
            item.get("contribution"),
            item.get("source_score"),
            item.get("guard_passed"),
            item.get("applied"),
        )
        item["receipt_line"] = _receipt_line(
            item["label"],
            item.get("contribution"),
        )
        components.append(item)

    positive = sum(
        max(float(item.get("contribution", 0) or 0), 0)
        for item in components
    )
    negative = sum(
        min(float(item.get("contribution", 0) or 0), 0)
        for item in components
    )

    receipt = [
        item["receipt_line"]
        for item in components
        if abs(float(item.get("contribution", 0) or 0)) > 0.001
    ]

    if floor_applied:
        receipt.append(
            f"안전장치: {float(score_before_floor or 0):.2f}점 → "
            f"{float(final_score or 0):.2f}점"
        )

    receipt.append(
        f"최종 위험점수: {float(final_score or 0):.2f}점 "
        f"({_risk_level_korean(risk_level)})"
    )

    return {
        "event_id": int(event_id),

        # 기존 필드 유지
        "formula": (
            "Base Risk + Personal Baseline×0.3 + Sequence×0.4 "
            "+ Peer Contribution - Adaptive Compensation"
        ),
        "rule_score": round(float(rule_score or 0), 2),
        "anomaly_score": round(float(anomaly_score or 0), 2),
        "components": components,
        "positive_contribution_total": round(positive, 2),
        "negative_contribution_total": round(negative, 2),
        "score_before_floor": round(float(score_before_floor or 0), 2),
        "floor_applied": bool(floor_applied),
        "floor_reason": floor_reason,
        "final_score": round(float(final_score or 0), 2),
        "risk_level": risk_level,
        "reasons": list(reasons or []),

        # 일반인용 Explainable Risk Score
        "plain_summary": _build_summary(
            final_score,
            risk_level,
            components,
            floor_applied,
            floor_reason,
        ),
        "decision_text": _build_decision_text(
            final_score,
            risk_level,
        ),
        "score_receipt": receipt,
        "threshold_guide": {
            "LOW": "0~23점: 낮음",
            "MEDIUM": "24~59점: 주의",
            "HIGH": "60~79점: 높음",
            "CRITICAL": "80~100점: 매우 높음",
        },
        "calculation_explanation": (
            "위험점수는 서로 다른 탐지 신호를 하나의 우선순위 값으로 묶어 "
            "어떤 이벤트부터 조사해야 하는지 결정하기 위한 값입니다. "
            "점수가 높다는 것은 한 가지 규칙만 위반했다는 뜻이 아니라, "
            "개인 행동 이탈·공격 흐름·동료 대비 차이 등 여러 맥락이 함께 "
            "위험하다고 판단됐음을 의미할 수 있습니다."
        ),
        "note": (
            "Dynamic User Risk와 Incident Correlation Score는 별도 계층이며 "
            "이 Event Risk 계산식에 다시 합산되지 않습니다."
        )
    }


def save_risk_explanation(db: Session, event_id: int, explanation: dict):
    existing = (
        db.query(EventRiskExplanation)
        .filter(EventRiskExplanation.event_id == event_id)
        .first()
    )

    payload = json.dumps(explanation, ensure_ascii=False)

    if existing:
        existing.explanation_json = payload
    else:
        existing = EventRiskExplanation(
            event_id=event_id,
            explanation_json=payload
        )
        db.add(existing)

    db.commit()
    db.refresh(existing)
    return explanation


def get_risk_explanation(db: Session, event_id: int):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )

    if event is None:
        return None

    row = (
        db.query(EventRiskExplanation)
        .filter(EventRiskExplanation.event_id == event_id)
        .first()
    )

    if row is not None:
        data = json.loads(row.explanation_json)

        # 예전 설명 JSON도 새 화면에서 안전하게 표시되도록 기본값 보충
        data.setdefault(
            "plain_summary",
            (
                f"최종 위험점수는 {float(data.get('final_score', 0) or 0):.2f}점이며 "
                f"위험 등급은 {_risk_level_korean(data.get('risk_level'))}입니다."
            )
        )
        data.setdefault(
            "decision_text",
            _build_decision_text(
                data.get("final_score", 0),
                data.get("risk_level"),
            )
        )
        data.setdefault("score_receipt", [])
        data.setdefault(
            "threshold_guide",
            {
                "LOW": "0~23점: 낮음",
                "MEDIUM": "24~59점: 주의",
                "HIGH": "60~79점: 높음",
                "CRITICAL": "80~100점: 매우 높음",
            }
        )
        return data

    reasons = []
    if event.reasons:
        reasons = [
            item.strip()
            for item in str(event.reasons).split(",")
            if item.strip()
        ]

    final_score = float(event.risk_score or 0)
    risk_level = event.risk_level

    return {
        "event_id": event.id,
        "historical_fallback": True,
        "formula": None,
        "components": [],
        "score_before_floor": None,
        "floor_applied": None,
        "floor_reason": None,
        "final_score": final_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "plain_summary": (
            f"최종 위험점수는 {final_score:.2f}점이며 "
            f"위험 등급은 {_risk_level_korean(risk_level)}입니다."
        ),
        "decision_text": _build_decision_text(final_score, risk_level),
        "score_receipt": [],
        "threshold_guide": {
            "LOW": "0~23점: 낮음",
            "MEDIUM": "24~59점: 주의",
            "HIGH": "60~79점: 높음",
            "CRITICAL": "80~100점: 매우 높음",
        },
        "note": (
            "이 이벤트는 Explainable Risk Score 기능 도입 전에 저장되어 "
            "정확한 당시 구성 점수는 보존되어 있지 않습니다. "
            "최종 Risk Score와 저장된 탐지 근거만 표시합니다."
        )
    }
