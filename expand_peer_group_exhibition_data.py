from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import random

from server.database import SessionLocal
from server.models import MonitoredUser, SecurityEvent
from server.baseline_engine import get_user_behavior_profile, get_peer_group_profile
import prepare_exhibition_data_30000 as base

RANDOM_SEED = 2026111603
HISTORY_DAYS = 90
TARGET_NEW_EVENTS = 28000
random.seed(RANDOM_SEED)
base.random.seed(RANDOM_SEED)


@dataclass(frozen=True)
class PeerSpec:
    base_user: str
    username: str
    display_name: str
    host: str
    ip: str
    start_delta: int = 0
    end_delta: int = 0
    evening_factor: float = 1.0
    weekend_factor: float = 1.0
    usb_factor: float = 1.0
    volume_factor: float = 1.0
    process_boosts: tuple[str, ...] = ()
    extra_files: tuple[str, ...] = ()


PEER_SPECS = (
    PeerSpec('dev01','be02','김민준','DEV-BE-02','10.10.10.121',-1,0,.85,.75,1.0,1.06,('python.exe','DBeaver.exe','Postman.exe'),('api_performance_test.json','db_migration_plan.sql')),
    PeerSpec('dev01','be03','서준혁','DEV-BE-03','10.10.10.122',1,1,1.35,1.25,1.0,1.13,('docker.exe','WindowsTerminal.exe','git.exe'),('container_debug.md','deployment_notes.yaml')),
    PeerSpec('dev02','fe02','정시우','DEV-FE-02','10.10.10.123',0,-1,.82,.70,1.0,.98,('Code.exe','Figma.exe','chrome.exe'),('component_spec.fig','accessibility_checklist.md')),
    PeerSpec('dev02','fe03','한지호','DEV-FE-03','10.10.10.124',1,1,1.30,1.20,1.0,1.10,('node.exe','npm.cmd','git.exe'),('bundle_report.json','frontend_release_notes.md')),
    PeerSpec('dev03','data02','박지훈','DEV-DATA-02','10.10.10.125',-1,0,.80,.75,1.0,1.08,('python.exe','DBeaver.exe','PowerBI.exe'),('warehouse_quality.sql','etl_validation.xlsx')),
    PeerSpec('dev03','data03','강민석','DEV-DATA-03','10.10.10.126',1,1,1.35,1.30,1.0,1.16,('python.exe','java.exe','docker.exe'),('spark_tuning.md','pipeline_monitoring.json')),
    PeerSpec('dev04','qa02','이수현','QA-PC-02','10.10.10.127',-1,0,.75,.70,1.0,.95,('Postman.exe','chrome.exe','EXCEL.EXE'),('manual_regression.xlsx','api_evidence.json')),
    PeerSpec('dev04','qa03','조현민','QA-PC-03','10.10.10.128',0,1,1.25,1.20,1.0,1.08,('python.exe','Code.exe','WindowsTerminal.exe'),('automation_suite.py','nightly_test_result.xml')),

    PeerSpec('office01','hr02','김하윤','HR-PC-02','10.10.20.131',-1,-1,.60,.50,1.0,.92,('EXCEL.EXE','OUTLOOK.EXE','Teams.exe'),('interview_schedule.xlsx','onboarding_checklist.docx')),
    PeerSpec('office01','hr03','박예린','HR-PC-03','10.10.20.132',0,0,1.20,.85,1.0,1.03,('WINWORD.EXE','POWERPNT.EXE','AcroRd32.exe'),('benefit_policy_review.docx','training_plan.pptx')),
    PeerSpec('office02','office03','최유진','ADM-OFFICE-02','10.10.20.133',-1,0,.70,.60,1.0,.94,('OUTLOOK.EXE','Teams.exe','OneDrive.exe'),('facility_schedule.xlsx','vendor_contract_list.xlsx')),
    PeerSpec('office02','office04','문서연','ADM-OFFICE-03','10.10.20.134',0,1,1.25,1.0,1.0,1.05,('EXCEL.EXE','POWERPNT.EXE','WINWORD.EXE'),('quarterly_purchase.xlsx','office_event_plan.pptx')),

    PeerSpec('finance01','finance03','신도윤','FIN-PC-03','10.10.30.141',-1,0,.75,.60,1.0,.97,('EXCEL.EXE','PowerBI.exe','AcroRd32.exe'),('cash_position.xlsx','forecast_variance.xlsx')),
    PeerSpec('finance01','finance04','오민재','FIN-PC-04','10.10.30.142',0,1,1.30,1.20,1.0,1.10,('EXCEL.EXE','OUTLOOK.EXE','PowerBI.exe'),('board_finance_pack.xlsx','scenario_model.xlsx')),
    PeerSpec('finance02','acct02','이지은','ACC-PC-02','10.10.30.143',-1,0,.80,.65,1.0,.96,('EXCEL.EXE','AcroRd32.exe','calc.exe'),('vat_reconciliation.xlsx','invoice_register.xlsx')),
    PeerSpec('finance02','acct03','김채원','ACC-PC-03','10.10.30.144',0,1,1.25,1.15,1.0,1.09,('EXCEL.EXE','OneDrive.exe','OUTLOOK.EXE'),('month_end_close.xlsx','audit_support.xlsx')),

    PeerSpec('sales01','sales02','백승우','SALES-PC-02','10.10.40.151',-1,0,.80,.70,1.20,1.05,('OUTLOOK.EXE','Teams.exe','EXCEL.EXE'),('regional_pipeline.xlsx','customer_followup.xlsx')),
    PeerSpec('sales01','sales03','남도현','SALES-PC-03','10.10.40.152',0,1,1.30,1.30,1.35,1.12,('POWERPNT.EXE','chrome.exe','OneDrive.exe'),('enterprise_proposal.pptx','field_visit_schedule.xlsx')),

    PeerSpec('design01','design02','유나경','DESIGN-PC-02','10.10.60.161',-1,0,.80,.80,1.0,1.00,('Figma.exe','Illustrator.exe','chrome.exe'),('mobile_flow.fig','icon_library.ai')),
    PeerSpec('design01','design03','송지아','DESIGN-PC-03','10.10.60.162',1,1,1.35,1.30,1.0,1.12,('Photoshop.exe','Figma.exe','Acrobat.exe'),('campaign_visual.psd','prototype_feedback.pdf')),
    PeerSpec('plan01','plan02','정다은','PLAN-PC-02','10.10.60.163',-1,0,.75,.70,1.0,.96,('POWERPNT.EXE','EXCEL.EXE','Teams.exe'),('sprint_roadmap.pptx','feature_matrix.xlsx')),
    PeerSpec('plan01','plan03','박건우','PLAN-PC-03','10.10.60.164',0,1,1.25,1.20,1.0,1.08,('Figma.exe','WINWORD.EXE','chrome.exe'),('new_service_spec.docx','user_flow.fig')),

    PeerSpec('admin01','admin02','장현수','ADMIN-PC-02','10.10.50.12',-1,0,.85,.80,.80,1.07,('mmc.exe','eventvwr.exe','mstsc.exe'),('windows_patch_log.xlsx','server_health_check.txt')),
    PeerSpec('admin01','admin03','류재훈','ADMIN-PC-03','10.10.50.13',1,1,1.35,1.35,1.20,1.15,('powershell.exe','WindowsTerminal.exe','WinSCP.exe'),('night_operation_log.txt','remote_admin_checklist.docx')),
    PeerSpec('security01','security02','권민호','SOC-PC-02','10.10.50.14',-1,0,.85,.85,.70,1.08,('Wireshark.exe','eventvwr.exe','chrome.exe'),('packet_analysis.pcap.txt','ioc_review.xlsx')),
    PeerSpec('security01','security03','윤서진','SOC-PC-03','10.10.50.15',1,1,1.35,1.35,.80,1.14,('powershell.exe','WindowsTerminal.exe','WinSCP.exe'),('threat_hunt_query.txt','incident_timeline.xlsx')),

    PeerSpec('manager01','manager02','김태성','MGR-PC-02','10.10.70.72',-1,-1,.70,.65,1.0,.94,('OUTLOOK.EXE','EXCEL.EXE','Teams.exe'),('weekly_exec_report.xlsx','division_budget.xlsx')),
    PeerSpec('manager01','manager03','서현우','MGR-PC-03','10.10.70.73',0,1,1.25,1.10,1.0,1.07,('POWERPNT.EXE','WINWORD.EXE','AcroRd32.exe'),('strategy_review.pptx','executive_brief.docx')),
)

BASE_USERS = {p.username: p for p in base.USERS}


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def adjusted_processes(original, spec):
    rows = []
    for i, (name, weight) in enumerate(original.processes):
        factor = 1.45 if name in spec.process_boosts else 1.0
        jitter = 0.88 + ((i * 17 + len(spec.username) * 11) % 23) / 100
        rows.append((name, max(1, round(weight * factor * jitter))))
    return tuple(rows)


def make_peer_profile(spec):
    o = BASE_USERS[spec.base_user]
    start = clamp(o.weekday_start + spec.start_delta, 6, 12)
    end = clamp(o.weekday_end + spec.end_delta, start + 6, 23)
    files = tuple(dict.fromkeys(list(o.files) + list(spec.extra_files)))

    return base.UserProfile(
        username=spec.username,
        display_name=spec.display_name,
        department=o.department,
        role=o.role,
        category=o.category,
        host=spec.host,
        ip=spec.ip,
        processes=adjusted_processes(o, spec),
        files=files,
        weekday_start=start,
        weekday_end=end,
        evening_probability=clamp(o.evening_probability * spec.evening_factor, .005, .60),
        evening_end=o.evening_end,
        weekend_probability=clamp(o.weekend_probability * spec.weekend_factor, .002, .40),
        usb_probability=clamp(o.usb_probability * spec.usb_factor, .0005, .025),
        volume_weight=o.volume_weight * spec.volume_factor,
        process_ratio=o.process_ratio,
        file_ratio=o.file_ratio,
        login_ratio=o.login_ratio,
    )


NEW_USERS = tuple(make_peer_profile(s) for s in PEER_SPECS)


def backdate_registration(db, profile):
    row = db.query(MonitoredUser).filter(MonitoredUser.username == profile.username).first()
    if row is not None and hasattr(row, 'created_at'):
        row.created_at = (datetime.now() - timedelta(days=HISTORY_DAYS + 1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )


def build_interleaved_bulk_rows(profiles, counts, medium_counts):
    rows = []
    end = datetime.now() - timedelta(minutes=5)
    start = base.date_range_start(HISTORY_DAYS)

    for profile in profiles:
        count = counts[profile.username]
        medium_count = medium_counts[profile.username]
        anomaly_indexes = set(random.sample(range(count), k=min(medium_count, count)))

        for serial in range(count):
            ts = base.choose_work_timestamp(profile, start, end)
            rows.append(base.build_bulk_event(
                profile=profile,
                timestamp=ts,
                kind=base.event_kind(profile),
                is_medium_anomaly=serial in anomaly_indexes,
                serial=serial,
            ))

    rows.sort(key=lambda e: (e.timestamp or datetime.min, e.user or ''))
    return rows


def insert_rows(db, rows):
    total = 0
    batch = []
    for row in rows:
        batch.append(row)
        if len(batch) >= 500:
            db.add_all(batch)
            db.commit()
            total += len(batch)
            batch.clear()
    if batch:
        db.add_all(batch)
        db.commit()
        total += len(batch)
    return total


def count_user_events(db, username):
    return int(db.query(SecurityEvent).filter(SecurityEvent.user == username).count())


def persona_line(profile):
    top = sorted(profile.processes, key=lambda x: x[1], reverse=True)[:5]
    return (
        f"시간 {profile.weekday_start:02d}~{profile.weekday_end:02d}시 | "
        f"야간 {profile.evening_probability*100:.1f}% | "
        f"주말 {profile.weekend_probability*100:.1f}% | "
        f"USB {profile.usb_probability*100:.2f}% | "
        f"선호 {', '.join(n for n,_ in top)}"
    )


def main():
    if len(NEW_USERS) != 28:
        raise RuntimeError(f'신규 Peer 수 오류: {len(NEW_USERS)}')

    db = SessionLocal()
    try:
        print('=' * 88)
        print('SENTINEL PEER GROUP EXHIBITION EXPANSION')
        print('=' * 88)
        print(f'기존 직무 사용자 : {len(base.USERS)}명')
        print(f'신규 Peer        : {len(NEW_USERS)}명')
        print(f'신규 이벤트 목표 : {TARGET_NEW_EVENTS:,}건')
        print(f'최종 예상 사용자 : {len(base.USERS) + len(NEW_USERS) + 1}명')
        print('기존 14명 / siem_demo / CERT 데이터는 보존합니다.')

        print('\n[1/6] 신규 Peer 사용자 등록')
        for p in NEW_USERS:
            base.ensure_monitored_user(db, p)
            backdate_registration(db, p)
        db.commit()
        print(f'  {len(NEW_USERS)}명 등록 완료')

        print('\n[2/6] 재실행 안전 초기화 - 신규 28명 데이터만 삭제')
        for p in NEW_USERS:
            deleted = base.reset_synthetic_user(db, p.username)
            print(f'  {p.username:<10} 삭제 {deleted:>5,}건')
        db.commit()
        for p in NEW_USERS:
            backdate_registration(db, p)
        db.commit()

        print('\n[3/6] 실제 UEBA 파이프라인 학습')
        learning_total = 0
        for p in NEW_USERS:
            c = base.seed_learning_events(db, p, HISTORY_DAYS)
            learning_total += c
            s = base.behavior_summary(db, p.username)
            print(
                f'  {p.username:<10} {c:>3}건 | '
                f"ACCEPTED={s.get('ACCEPTED',0):>2} "
                f"OBS={s.get('OBSERVING',0):>2} REJ={s.get('REJECTED',0):>2}"
            )

        print('\n[4/6] 90일 개인별 업무 이력 생성 및 시간순 교차 삽입')
        bulk_target = TARGET_NEW_EVENTS - learning_total
        bulk_counts = base.allocate_counts(NEW_USERS, bulk_target)
        medium_counts = base.allocate_counts(NEW_USERS, round(TARGET_NEW_EVENTS * .006))
        rows = build_interleaved_bulk_rows(NEW_USERS, bulk_counts, medium_counts)
        inserted = insert_rows(db, rows)
        print(f'  Bulk {inserted:,}건 삽입 완료')

        print('\n[5/6] 개인차 / Baseline 검증')
        high_count = 0
        for p in NEW_USERS:
            prof = get_user_behavior_profile(db=db, user=p.username)
            confidence = str(prof.get('confidence_level', prof.get('learning_status','UNKNOWN'))).upper()
            if confidence == 'HIGH':
                high_count += 1
            print(f'  {p.username:<10} {p.display_name:<8} | {p.department} / {p.role}')
            print(f'    {persona_line(p)}')
            print(f"    이벤트 {count_user_events(db,p.username):,}건 | Baseline {confidence} | LOW 학습 {prof.get('event_count',0)}건")

        print('\n[6/6] 기존 14명 Peer Group READY 검증')
        failures = []
        for original in base.USERS:
            peer = get_peer_group_profile(db=db, user=original.username)
            ok = bool(peer.get('available'))
            if not ok:
                failures.append(original.username)
            print(
                f"  [{'PASS' if ok else 'FAIL'}] {original.username:<10} "
                f"{peer.get('group_key','-'):<38} "
                f"Peers={peer.get('peer_user_count',0):>2} Events={peer.get('peer_event_count',0):>5}"
            )

        total_events = int(db.query(SecurityEvent).count())
        active_users = int(db.query(MonitoredUser).filter(MonitoredUser.monitoring_enabled == 1).count())
        new_names = [p.username for p in NEW_USERS]
        new_high = int(db.query(SecurityEvent).filter(SecurityEvent.user.in_(new_names), SecurityEvent.risk_level == 'HIGH').count())
        new_critical = int(db.query(SecurityEvent).filter(SecurityEvent.user.in_(new_names), SecurityEvent.risk_level == 'CRITICAL').count())

        print('\n' + '=' * 88)
        print('FINAL')
        print('=' * 88)
        print(f'활성 모니터링 사용자     : {active_users}명')
        print(f'전체 SecurityEvent     : {total_events:,}건')
        print(f'신규 Peer Baseline HIGH: {high_count}/{len(NEW_USERS)}')
        print(f'신규 Peer HIGH          : {new_high}')
        print(f'신규 Peer CRITICAL      : {new_critical}')

        if not failures and high_count == len(NEW_USERS) and new_high == 0 and new_critical == 0:
            print('\n[READY] 14개 기존 직무 모두 실제 Peer Group 비교 준비 완료')
        else:
            print('\n[REVIEW] 확인이 필요한 항목이 있습니다.')
            if failures:
                print('Peer 미준비:', ', '.join(failures))

        print('\n재실행해도 신규 28명 데이터만 다시 생성됩니다.')

    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == '__main__':
    main()
