import os
import json

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise ValueError(
        "OPENAI_API_KEY가 설정되어 있지 않습니다. "
        "프로젝트 루트의 .env 파일을 확인하세요."
    )

client = OpenAI(api_key=api_key)


def analyze_security_incident(
    user,
    event_type,
    risk_score,
    risk_level,
    reasons,
    source_ip=None,
    file_name=None,
    file_grade=None,
    process_name=None
):
    if isinstance(reasons, list):
        reasons_text = "\n".join(
            f"- {reason}" for reason in reasons
        )
    else:
        reasons_text = str(reasons)

    prompt = f"""
너는 기업의 SOC(Security Operations Center)에서 근무하는
사이버 보안 분석가다.

아래 정보는 SIEM/UEBA 시스템에서 실제로 탐지된 보안 이벤트다.

탐지된 정보만을 근거로 분석하고,
확인되지 않은 사실을 확정적으로 말하지 마라.

[탐지 이벤트]

사용자: {user}
이벤트 유형: {event_type}
위험 점수: {risk_score}
위험 등급: {risk_level}
출발지 IP: {source_ip or "정보 없음"}
파일 이름: {file_name or "정보 없음"}
파일 등급: {file_grade or "정보 없음"}
프로세스: {process_name or "정보 없음"}

[SIEM 탐지 근거]

{reasons_text}

다음 JSON 형식으로만 응답하라.

{{
    "summary": "탐지된 보안 이벤트를 2~3문장으로 설명",
    "threat_scenario": "가능성이 있는 위협 시나리오",
    "evidence": ["판단 근거 1", "판단 근거 2"],
    "recommendations": ["대응 권고 1", "대응 권고 2", "대응 권고 3"]
}}

모든 내용은 한국어로 작성한다.
"""

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt
    )

    result_text = response.output_text.strip()

    if result_text.startswith("```"):
        result_text = result_text.replace("```json", "", 1)
        result_text = result_text.replace("```", "").strip()

    try:
        return json.loads(result_text)
    except json.JSONDecodeError:
        return {
            "summary": result_text,
            "threat_scenario": "분석 결과 구조화 실패",
            "evidence": [],
            "recommendations": []
        }


def analyze_incident_with_ai(
    incident,
    events,
    dynamic_user_risk=None
):
    evidence_events = []

    for event in events:
        reasons = []

        if getattr(event, "reasons", None):
            reasons = [
                value.strip()
                for value in event.reasons.split(",")
                if value.strip()
            ]

        evidence_events.append({
            "event_id": event.id,
            "timestamp": (
                event.timestamp.isoformat()
                if event.timestamp
                else None
            ),
            "event_type": event.event_type,
            "risk_score": event.risk_score,
            "risk_level": event.risk_level,
            "source_ip": event.source_ip,
            "login_success": event.login_success,
            "login_fail_count": event.login_fail_count,
            "file_name": event.file_name,
            "file_grade": event.file_grade,
            "file_access_count": event.file_access_count,
            "usb_connected": event.usb_connected,
            "process_name": event.process_name,
            "reasons": reasons
        })

    context = {
        "incident": incident,
        "related_security_events": evidence_events,
        "dynamic_user_risk": dynamic_user_risk
    }

    prompt = f"""
너는 기업 SOC의 선임 사이버 보안 분석가다.

아래 JSON은 SIEM/UEBA 시스템이 계산한 하나의 보안 사고 전체 컨텍스트다.
탐지 점수나 공격 여부를 새로 계산하지 말고, 제공된 구조화 증거를 종합하여
SOC 분석가가 조사에 사용할 보고서를 작성하라.

반드시 지킬 원칙:
1. 제공되지 않은 사실을 만들지 않는다.
2. 관측된 사실과 추론/가능성을 분리한다.
3. USB 연결만으로 실제 파일 반출을 확정하지 않는다.
4. 프로세스 실행만으로 C2 또는 외부 전송을 확정하지 않는다.
5. MITRE confidence가 LOW/NONE이면 확정된 공격 기법처럼 표현하지 않는다.
6. 대응 권고는 검토/조사/격리 권고이며 실행했다고 말하지 않는다.
7. Event Risk, Dynamic User Risk, Incident Correlation Score를 서로 다른 지표로 취급한다.

[구조화된 사고 증거]
{json.dumps(context, ensure_ascii=False, default=str, indent=2)}

아래 JSON 형식으로만 응답하라.

{{
  "incident_summary": "사고 전체를 3~5문장으로 요약",
  "threat_scenario": "현재 증거로 가능한 위협 시나리오",
  "confirmed_facts": ["로그로 직접 확인된 사실"],
  "uncertainties": ["현재 증거만으로 확인되지 않은 사실"],
  "attack_flow_analysis": "Storyline 시간 순서 기반 공격 흐름 분석",
  "mitre_analysis": [
    {{
      "technique_id": "Txxxx 또는 미확정",
      "interpretation": "매핑 의미와 증거 강도"
    }}
  ],
  "key_evidence": ["가장 중요한 조사 근거"],
  "investigation_priorities": ["우선 확인할 조사 항목"],
  "response_recommendations": ["관리자가 검토할 대응 권고"],
  "analyst_caution": "과잉 판단을 막기 위한 주의사항"
}}

모든 내용은 한국어로 작성한다.
"""

    response = client.responses.create(
        model="gpt-5.6-luna",
        input=prompt
    )

    result_text = response.output_text.strip()

    if result_text.startswith("```"):
        result_text = result_text.replace("```json", "", 1)
        result_text = result_text.replace("```", "").strip()

    try:
        return json.loads(result_text)
    except json.JSONDecodeError:
        return {
            "incident_summary": result_text,
            "threat_scenario": "분석 결과 구조화 실패",
            "confirmed_facts": [],
            "uncertainties": [],
            "attack_flow_analysis": "",
            "mitre_analysis": [],
            "key_evidence": [],
            "investigation_priorities": [],
            "response_recommendations": [],
            "analyst_caution": ""
        }
