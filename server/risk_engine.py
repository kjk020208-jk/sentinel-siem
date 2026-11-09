from datetime import datetime


def calculate_rule_risk(event):
    score = 0
    reasons = []

    # 1. 비정상 시간 접근
    current_hour = (
        event.timestamp.hour
        if getattr(event, "timestamp", None) is not None
        else datetime.now().hour
    )

    if current_hour < 6 or current_hour >= 22:
        score += 15
        reasons.append("비정상 시간대 접근")

    # 2. 로그인 실패
    if event.login_fail_count >= 3:
        score += 15
        reasons.append("반복적인 로그인 실패")

    # 3. 파일 중요도
    if event.file_grade == "내부":
        score += 10
        reasons.append("내부 문서 접근")

    elif event.file_grade == "대외비":
        score += 25
        reasons.append("대외비 문서 접근")

    # 4. 대량 파일 접근
    if event.file_access_count >= 20:
        score += 20
        reasons.append("단시간 내 대량 파일 접근")

    # 5. USB 연결
    # USB 연결 자체는 정상 업무에서도 자주 발생할 수 있으므로
    # 단독으로 MEDIUM을 만들지 않도록 기본 점수만 부여한다.
    # 실제 위험도는 개인 기준선과 USB-파일 행동 시퀀스에서 추가 반영한다.
    if event.usb_connected == 1:
        score += 5
        reasons.append("USB 저장장치 연결(기본 위험)")

    # 6. 외부 전송 가능 프로세스
    suspicious_processes = [
        "chrome.exe",
        "msedge.exe",
        "outlook.exe"
    ]

    if event.process_name:
        if event.process_name.lower() in suspicious_processes:
            score += 10
            reasons.append("외부 전송 가능 프로세스 실행")

    # 최대 100점
    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 24:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, reasons


# Rule 기반 점수 + Isolation Forest 이상 점수를 합쳐
# 최종 Risk Score를 계산
def calculate_final_risk(rule_score, anomaly_score):
    rule_weight = 0.7
    ml_weight = 0.3

    final_score = (
        rule_score * rule_weight
        + anomaly_score * ml_weight
    )

    final_score = round(min(final_score, 100), 2)

    if final_score >= 80:
        level = "CRITICAL"
    elif final_score >= 60:
        level = "HIGH"
    elif final_score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return final_score, level