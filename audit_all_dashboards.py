from pathlib import Path
from datetime import datetime
from sqlalchemy import text

from server.database import SessionLocal
from server.models import SecurityEvent, MonitoredUser

ROOT = Path("/app")
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"
MAIN = ROOT / "server" / "main.py"

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
results = []

def rec(status, area, detail):
    results.append((status, area, detail))
    print(f"[{status}] {area:<32} {detail}")

def section(title):
    print("\n" + "=" * 90)
    print(title)
    print("=" * 90)

def table_exists(db, name):
    return db.execute(text(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=:n"
    ), {"n": name}).first() is not None

def table_count(db, name):
    if not table_exists(db, name):
        return None
    return int(db.execute(text(f"SELECT COUNT(*) FROM {name}")).scalar() or 0)

def main():
    db = SessionLocal()
    try:
        print("=" * 90)
        print("SENTINEL DASHBOARD FULL AUDIT")
        print("=" * 90)
        print(f"검사 시각: {datetime.now():%Y-%m-%d %H:%M:%S}")
        print("현재 Railway DB + 현재 배포 App.jsx 읽기 전용 검사")

        if not APP.exists():
            rec(FAIL, "Frontend source", f"{APP} 없음")
            return

        app = APP.read_text(encoding="utf-8", errors="replace")
        mainpy = MAIN.read_text(encoding="utf-8", errors="replace") if MAIN.exists() else ""

        active_users = db.query(MonitoredUser).filter(
            MonitoredUser.monitoring_enabled == 1
        ).count()
        total_events = db.query(SecurityEvent).count()
        anomaly = db.query(SecurityEvent).filter(
            SecurityEvent.anomaly_score >= 50
        ).count()
        high = db.query(SecurityEvent).filter(
            SecurityEvent.risk_level == "HIGH"
        ).count()
        critical = db.query(SecurityEvent).filter(
            SecurityEvent.risk_level == "CRITICAL"
        ).count()

        # 1 Overview
        section("[1] 보안 현황")
        rec(PASS if "function OverviewV2" in app else FAIL,
            "OverviewV2", "컴포넌트 존재" if "function OverviewV2" in app else "없음")

        summary_ok = all(x in app for x in [
            "eventSummaryRaw", "api.eventSummary", "summary={eventSummaryRaw}"
        ])
        rec(PASS if summary_ok else FAIL, "전체 통계 Summary",
            f"DB Events {total_events:,} 기준 연결" if summary_ok else "최근 /events 배열 의존 가능성")

        behavior_ok = all(x in app for x in [
            "behaviorChangesRaw", "api.behaviorChanges",
            "behaviorChanges={behaviorChangesRaw}", "const behaviorRows=arr("
        ])
        rec(PASS if behavior_ok else FAIL, "Behavior Change 실제 집계",
            "실제 /behavior-changes 사용" if behavior_ok else "최근 이벤트 reasons 파싱 가능성")

        rec(PASS, "Overview 실제 DB 기준값",
            f"Events {total_events:,} · Anomaly {anomaly:,} · HIGH {high:,} · CRITICAL {critical:,} · Users {active_users}")

        # 2 Events
        section("[2] 이벤트 모니터링")
        sig_ok = "function EventsPage({events,monitoredUsers=[],summary})" in app
        rec(PASS if sig_ok else FAIL, "EventsPage Props",
            "summary + monitoredUsers" if sig_ok else "구형 events-only 시그니처 가능성")

        users_ok = "const monitoredUserNames=" in app
        rec(PASS if users_ok else FAIL, "사용자 필터",
            "모니터링 사용자 전체 목록 사용" if users_ok else "최근 이벤트에서만 사용자 추출 가능성")

        kpi_ok = "visibleEventCount" in app and "summary?.total_events" in app
        rec(PASS if kpi_ok else FAIL, "기본 KPI 전체 DB 기준",
            f"{total_events:,}건 표시 가능" if kpi_ok else "500건/filtered.length 표시 가능성")

        limit_ok = ".limit(safe_limit)" in mainpy
        rec(PASS if limit_ok else WARN, "라이브 이벤트 제한",
            "최근 구간만 조회하여 성능 유지" if limit_ok else "limit 구현 확인 필요")

        # 3 Incidents
        section("[3] 보안 사고 분석")
        checks = [
            ("Incident 상세", "api.incident(id)"),
            ("Playbook", "api.playbook(id)"),
            ("관련 이벤트 결합", "function incidentEvents("),
            ("Attack Storyline", "function Storyline("),
            ("Playbook UI", "function PlaybookView("),
            ("AI 분석 UI", "incidentAiError"),
        ]
        for name, needle in checks:
            rec(PASS if needle in app else FAIL, name,
                "연결됨" if needle in app else "누락")

        incident_table = None
        for t in ["incidents", "security_incidents", "incident_records"]:
            c = table_count(db, t)
            if c is not None:
                incident_table = (t, c)
                break
        rec(PASS if incident_table else WARN, "Incident DB",
            f"{incident_table[0]} · {incident_table[1]:,}건" if incident_table else "알려진 테이블명으로 확인 못함")

        # 4 Users
        section("[4] 사용자 행동 분석")
        direct_ok = (
            ("profile?._dashboard_recent_events" in app and
             "profile?._dashboard_total_event_count" in app)
            or "api.userEvents(selected)" in app
        )
        rec(PASS if direct_ok else FAIL, "선택 사용자 이벤트",
            "DB 직접 조회 경로 사용" if direct_ok else "최근 500건 events.filter 의존 가능성")

        backend_total_ok = (
            "_dashboard_total_event_count" in mainpy
            or '@app.get("/users/{username}/events")' in mainpy
        )
        rec(PASS if backend_total_ok else WARN, "선택 사용자 전체 건수",
            "백엔드 전체 건수 제공" if backend_total_ok else "데이터 경로 확인 필요")

        learning_users = db.execute(text("""
            SELECT user, COUNT(*) cnt
            FROM security_events
            WHERE risk_level='LOW'
              AND timestamp >= datetime('now','-30 days')
              AND user IN (
                'dev01','dev02','dev03','dev04','office01','office02',
                'finance01','finance02','sales01','design01','plan01',
                'admin01','security01','manager01'
              )
            GROUP BY user
        """)).mappings().all()
        lowmap = {str(r["user"]): int(r["cnt"]) for r in learning_users}
        baseline_ok = len(lowmap) == 14 and all(v >= 100 for v in lowmap.values())
        rec(PASS if baseline_ok else WARN, "Baseline 학습 데이터",
            "14명 모두 최근 30일 LOW 100건+" if baseline_ok else f"확인된 사용자 {len(lowmap)}/14")

        # 5 Behavior
        section("[5] 행동 승인 관리")
        review_ok = all(x in app for x in [
            "function BehaviorPage()", "api.behaviorChanges()",
            "api.behaviorDecision(", "OBSERVING", "ACCEPTED", "REJECTED"
        ])
        rec(PASS if review_ok else FAIL, "조회/판정 API",
            "조회 + 승인/거절/재관찰 연결" if review_ok else "필수 연결 누락")

        if table_exists(db, "behavior_change_observations"):
            rows = db.execute(text("""
                SELECT UPPER(COALESCE(status,'UNKNOWN')) status, COUNT(*) cnt
                FROM behavior_change_observations
                GROUP BY UPPER(COALESCE(status,'UNKNOWN'))
            """)).mappings().all()
            bc = {str(r["status"]): int(r["cnt"]) for r in rows}
            rec(PASS, "Behavior DB",
                f"OBSERVING {bc.get('OBSERVING',0)} · ACCEPTED {bc.get('ACCEPTED',0)} · REJECTED {bc.get('REJECTED',0)}")
        else:
            rec(FAIL, "Behavior DB", "테이블 없음")

        # 6 CERT
        section("[6] CERT 100K 검증")
        cert_needles = [
            'value="100,000"', 'value="2,993"', 'value="97,007"',
            'value="552"', 'value="5,619"', 'value="91,388"', 'value="2,441"',
            'value="8.95%"', 'value="18.44%"', 'value="5.79%"',
            'value="12.05%"', 'value="100%"'
        ]
        cert_ui_ok = all(x in app for x in cert_needles)
        rec(PASS if cert_ui_ok else FAIL, "CERT 핵심 수치",
            "100K/Confusion Matrix/성능지표 표시" if cert_ui_ok else "일부 수치 누락")

        tp, fp, tn, fn = 552, 5619, 91388, 2441
        precision = tp/(tp+fp)*100
        recall = tp/(tp+fn)*100
        fpr = fp/(fp+tn)*100
        f1 = 2*precision*recall/(precision+recall)
        math_ok = (
            tp+fn == 2993 and fp+tn == 97007 and tp+fp+tn+fn == 100000
            and round(precision,2) == 8.95
            and round(recall,2) == 18.44
            and round(fpr,2) == 5.79
            and round(f1,2) == 12.05
        )
        rec(PASS if math_ok else FAIL, "CERT 산술 일관성",
            "표시 수치 계산 일치" if math_ok else "수치 불일치")

        # 7 navigation
        section("[7] 6개 메뉴 라우팅")
        pages = ["overview","events","incidents","users","behavior","cert"]
        missing = [p for p in pages if f"page==='{p}'" not in app]
        rec(PASS if not missing else FAIL, "메뉴 렌더링",
            "6개 모두 연결" if not missing else "누락: " + ", ".join(missing))

        # final
        section("FINAL DASHBOARD AUDIT")
        p = sum(s == PASS for s,_,_ in results)
        w = sum(s == WARN for s,_,_ in results)
        f = sum(s == FAIL for s,_,_ in results)
        print(f"PASS : {p}")
        print(f"WARN : {w}")
        print(f"FAIL : {f}")
        print()
        if f == 0 and w == 0:
            print("[DASHBOARD READY] 6개 대시보드의 코드/데이터 연결에서 문제를 발견하지 못했습니다.")
        elif f == 0:
            print("[DASHBOARD REVIEW] FAIL은 없지만 WARN 항목을 확인해야 합니다.")
        else:
            print("[DASHBOARD NOT READY] FAIL 항목을 수정해야 합니다.")

    finally:
        db.close()

if __name__ == "__main__":
    main()
