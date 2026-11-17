import json
import os
from datetime import datetime, timedelta

from sqlalchemy import Column, DateTime, Float, Integer, String, Text

from server.database import Base
from server.models import SecurityEvent
from server.response_control_engine import ResponseControlAction, create_control_action
from server.next_action_inference import predict_next_actions_for_user


class ThreatPrediction(Base):
    __tablename__ = 'threat_predictions'

    id = Column(Integer, primary_key=True, index=True)
    user = Column(String, index=True, nullable=False)
    target_host = Column(String, index=True, nullable=True)
    current_stage = Column(String, index=True, nullable=False)
    threat_progress = Column(Integer, nullable=False, default=0)
    predicted_vector = Column(String, index=True, nullable=False, default='NONE')
    prediction_confidence = Column(Integer, nullable=False, default=0)
    response_level = Column(String, index=True, nullable=False, default='OBSERVE')
    recommended_control = Column(String, nullable=True)
    evidence_json = Column(Text, nullable=False, default='[]')
    source_event_id = Column(Integer, index=True, nullable=True)
    source_risk_score = Column(Float, nullable=True)
    sequence_score = Column(Float, nullable=True)
    baseline_score = Column(Float, nullable=True)
    peer_score = Column(Float, nullable=True)
    status = Column(String, index=True, nullable=False, default='OBSERVING')
    control_action_id = Column(Integer, index=True, nullable=True)
    decision_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)


PREDICTION_ENABLED = os.getenv('SENTINEL_PREDICTIVE_RESPONSE_ENABLED', 'true').strip().lower() in {'1','true','yes','on'}
AUTO_MICRO_CONTROL_ENABLED = os.getenv('SENTINEL_AUTO_MICRO_CONTROL_ENABLED', 'false').strip().lower() in {'1','true','yes','on'}
AUTO_PROGRESS_THRESHOLD = int(os.getenv('SENTINEL_AUTO_MICRO_CONTROL_PROGRESS', '80'))
AUTO_CONFIDENCE_THRESHOLD = int(os.getenv('SENTINEL_AUTO_MICRO_CONTROL_CONFIDENCE', '85'))
NETWORK_RESTRICT_PROGRESS_THRESHOLD = int(os.getenv('SENTINEL_NETWORK_RESTRICT_PROGRESS', '96'))
NETWORK_RESTRICT_CONFIDENCE_THRESHOLD = int(os.getenv('SENTINEL_NETWORK_RESTRICT_CONFIDENCE', '95'))


SUSPICIOUS_PROCESSES = {'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','certutil.exe','curl.exe','scp.exe','ftp.exe'}
LOGIN_FAILURE_TYPES = {'login_failure','login_failed','logon_failure'}
LOGIN_SUCCESS_TYPES = {'login_success','logon_success'}
USB_TYPES = {'usb_connected','usb_connection'}
FILE_TYPES = {'file_access','document_analysis'}
PROCESS_TYPES = {'process_execution'}

GRU_RISK_ACTIONS = {
    'LOGIN_FAILURE',
    'SENSITIVE_FILE_ACCESS',
    'MASS_FILE_ACCESS',
    'POWERSHELL',
    'SCRIPT_EXECUTION',
    'ARCHIVE_CREATE',
    'USB_COPY',
    'EXTERNAL_TRANSFER',
    'WEB_UPLOAD',
    'EMAIL_SEND',
}


def _serialize(row):
    if row is None:
        return None
    try:
        raw_evidence = json.loads(row.evidence_json or '[]')
    except Exception:
        raw_evidence = []

    evidence = []
    gru_meta = None
    for item in raw_evidence if isinstance(raw_evidence, list) else []:
        if isinstance(item, str) and item.startswith('GRU_META::'):
            try:
                gru_meta = json.loads(item.split('GRU_META::', 1)[1])
            except Exception:
                gru_meta = None
            continue
        evidence.append(item)
    return {
        'id': row.id,
        'user': row.user,
        'target_host': row.target_host,
        'current_stage': row.current_stage,
        'threat_progress': row.threat_progress,
        'predicted_vector': row.predicted_vector,
        'prediction_confidence': row.prediction_confidence,
        'response_level': row.response_level,
        'recommended_control': row.recommended_control,
        'evidence': evidence,
        'gru_next_action': (gru_meta or {}).get('gru_next_action'),
        'gru_risk_probability': (gru_meta or {}).get('gru_risk_probability'),
        'gru_progress_boost': (gru_meta or {}).get('gru_progress_boost', 0),
        'source_event_id': row.source_event_id,
        'source_risk_score': row.source_risk_score,
        'sequence_score': row.sequence_score,
        'baseline_score': row.baseline_score,
        'peer_score': row.peer_score,
        'status': row.status,
        'control_action_id': row.control_action_id,
        'decision_note': row.decision_note,
        'created_at': row.created_at,
        'updated_at': row.updated_at,
        'auto_micro_control_enabled': AUTO_MICRO_CONTROL_ENABLED,
    }


def _etype(e):
    return str(getattr(e, 'event_type', '') or '').lower().strip()


def _is_sensitive(e):
    grade = str(getattr(e, 'file_grade', '') or '').lower().strip()
    return any(x in grade for x in ['대외비','기밀','비밀','confidential','secret','restricted'])


def _is_usb(e):
    return _etype(e) in USB_TYPES or int(getattr(e, 'usb_connected', 0) or 0) > 0


def _is_suspicious_process(e):
    p = str(getattr(e, 'process_name', '') or '').lower().strip()
    return _etype(e) in PROCESS_TYPES and p in SUSPICIOUS_PROCESSES


def _is_login_failure(e):
    return _etype(e) in LOGIN_FAILURE_TYPES or int(getattr(e, 'login_fail_count', 0) or 0) > 0


def _is_login_success(e):
    return _etype(e) in LOGIN_SUCCESS_TYPES or (getattr(e, 'login_success', None) == 1 and _etype(e) not in LOGIN_FAILURE_TYPES)


def _recent_user_events(db, user, reference_time, limit=40, minutes=60):
    since = reference_time - timedelta(minutes=minutes)
    rows = (db.query(SecurityEvent)
        .filter(SecurityEvent.user == user, SecurityEvent.timestamp <= reference_time, SecurityEvent.timestamp >= since)
        .order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
        .limit(limit).all())
    return list(reversed(rows))


def _response_level(progress, confidence):
    if progress < 40:
        return 'OBSERVE'
    if progress < 60:
        return 'ENHANCED_MONITORING'
    if progress < 80:
        return 'PREPARE_CONTROL'
    return 'SELECTIVE_PREVENT' if confidence >= AUTO_CONFIDENCE_THRESHOLD else 'PREPARE_CONTROL'


def _control_active_or_pending(db, target_host, action_type):
    q = db.query(ResponseControlAction).filter(
        ResponseControlAction.action_type == str(action_type or '').upper().strip()
    )
    if target_host:
        q = q.filter(ResponseControlAction.target_host == target_host)

    rows = q.order_by(ResponseControlAction.id.desc()).limit(30).all()

    if any(
        r.operation == 'APPLY'
        and r.status in {'QUEUED', 'CLAIMED'}
        for r in rows
    ):
        return True

    completed = [
        r for r in rows
        if r.status == 'COMPLETED'
        and r.operation in {'APPLY', 'RELEASE'}
    ]

    if not completed:
        return False

    return max(completed, key=lambda r: r.id).operation == 'APPLY'


def _usb_control_active_or_pending(db, target_host):
    return _control_active_or_pending(
        db,
        target_host,
        'USB_WRITE_RESTRICT',
    )


def evaluate_threat_prediction(db, *, user, reference_time, source_event_id=None, risk_score=0, sequence_score=0, baseline_score=0, peer_score=0, target_host=None):
    if not PREDICTION_ENABLED:
        return None

    events = _recent_user_events(db, user, reference_time)
    if not events:
        return None

    failures = [e for e in events if _is_login_failure(e)]
    first_failure = failures[0].timestamp if failures else None
    successes = [e for e in events if _is_login_success(e) and (first_failure is None or e.timestamp >= first_failure)]
    first_success = successes[0].timestamp if successes else None
    sensitive = [e for e in events if _etype(e) in FILE_TYPES and _is_sensitive(e) and (first_success is None or e.timestamp >= first_success)]
    first_sensitive = sensitive[0].timestamp if sensitive else None
    usb = [e for e in events if _is_usb(e) and (first_sensitive is None or e.timestamp >= first_sensitive)]
    first_usb = usb[0].timestamp if usb else None
    procs = [e for e in events if _is_suspicious_process(e) and (first_usb is None or e.timestamp >= first_usb)]

    failure_count = sum(max(1, int(getattr(e, 'login_fail_count', 0) or 0)) for e in failures)
    evidence = []
    if failure_count:
        evidence.append(f'최근 60분 로그인 실패 신호 {failure_count}회')
    if failures and successes:
        evidence.append('로그인 실패 이후 로그인 성공 확인')
    if sensitive:
        grade = getattr(sensitive[-1], 'file_grade', None)
        evidence.append('민감 문서 접근 확인' + (f' · {grade}' if grade else ''))
    if usb:
        evidence.append('민감 문서 접근 이후 USB 사용 확인')
    if procs:
        process_name = getattr(procs[-1], 'process_name', None) or 'unknown'
        if usb:
            evidence.append(f"USB 단계 이후 의심 프로세스 실행 · {process_name}")
        else:
            evidence.append(f"의심 프로세스 실행 · {process_name}")
    if float(baseline_score or 0) >= 30:
        evidence.append(f'개인 Baseline 이탈 점수 {float(baseline_score):.1f}')
    if float(peer_score or 0) >= 40:
        evidence.append(f'Peer Group 이탈 점수 {float(peer_score):.1f}')
    if float(sequence_score or 0) >= 40:
        evidence.append(f'Sequence Detection 점수 {float(sequence_score):.1f}')
    if float(risk_score or 0) >= 60:
        evidence.append(f'Event Risk {float(risk_score):.1f}')

    stage, progress, vector = 'NORMAL_ACTIVITY', 5, 'NONE'
    if failure_count >= 1:
        stage, progress, vector = 'ACCESS_ATTEMPT', 20, 'ACCOUNT_COMPROMISE'
    if failure_count >= 3:
        progress = 30
    if failures and successes:
        stage, progress, vector = 'ACCOUNT_ACCESS', 42, 'SENSITIVE_DATA_ACCESS'
    if sensitive:
        stage, progress, vector = 'SENSITIVE_DATA_ACCESS', 65, 'USB_EXFILTRATION'
    if sensitive and usb:
        stage, progress, vector = 'DEVICE_PREPARATION', 85, 'USB_EXFILTRATION'
    if sensitive and usb and procs:
        stage, progress, vector = 'EXFILTRATION_PREPARATION', 95, 'POTENTIAL_EXFILTRATION'

    progress += min(5, int(float(sequence_score or 0) / 20))
    progress += min(3, int(float(risk_score or 0) / 30))
    progress = max(0, min(100, int(progress)))

    # ------------------------------------------------------------
    # GRU learned next-action signal
    # ------------------------------------------------------------
    # GRU probability is separate from prediction_confidence.
    # It provides only a small progression boost and cannot by itself
    # trigger USB_WRITE_RESTRICT.
    try:
        gru_next_action = predict_next_actions_for_user(
            db,
            SecurityEvent,
            user=user,
            top_k=3,
            reference_time=reference_time,
            host=(target_host or None),
        )
    except Exception as gru_error:
        gru_next_action = {
            'available': False,
            'reason': str(gru_error),
            'predictions': [],
        }

    gru_risk_probability = 0.0
    gru_progress_boost = 0

    if gru_next_action and gru_next_action.get('available'):
        gru_predictions = gru_next_action.get('predictions') or []

        top3_text = []
        for pred in gru_predictions:
            action = str(pred.get('action') or '').upper()
            probability = float(pred.get('probability') or 0.0)
            top3_text.append(f"{action} {probability * 100.0:.1f}%")
            if action in GRU_RISK_ACTIONS:
                gru_risk_probability = max(gru_risk_probability, probability)

        if top3_text:
            evidence.append(
                'GRU Next-Action Top-3 · ' + ' / '.join(top3_text)
            )

        if gru_risk_probability >= 0.60:
            gru_progress_boost = 5
        elif gru_risk_probability >= 0.35:
            gru_progress_boost = 3
        elif gru_risk_probability >= 0.20:
            gru_progress_boost = 1

        if gru_progress_boost:
            progress = min(100, progress + gru_progress_boost)
            evidence.append(
                f'GRU 위험행동 보조 신호 +{gru_progress_boost} '
                f'(최대 위험행동 확률 {gru_risk_probability * 100.0:.1f}%)'
            )

    confidence = 20
    confidence += 12 if failure_count >= 3 else (5 if failure_count else 0)
    confidence += 12 if failures and successes else 0
    confidence += 22 if sensitive else 0
    confidence += 25 if usb else 0
    confidence += 8 if procs else 0
    confidence += 8 if float(sequence_score or 0) >= 60 else (4 if float(sequence_score or 0) >= 40 else 0)
    confidence += 4 if float(baseline_score or 0) >= 30 else 0
    confidence += 4 if float(peer_score or 0) >= 40 else 0
    confidence = max(0, min(99, int(confidence)))

    response_level = _response_level(progress, confidence)
    recommended_control = None
    if (
        vector in {'USB_EXFILTRATION', 'POTENTIAL_EXFILTRATION'}
        and sensitive
        and usb
        and progress >= AUTO_PROGRESS_THRESHOLD
        and confidence >= AUTO_CONFIDENCE_THRESHOLD
    ):
        recommended_control = 'USB_WRITE_RESTRICT'
        # Progressive Escalation
        if (
            vector in {'USB_EXFILTRATION', 'POTENTIAL_EXFILTRATION'}
            and sensitive
            and progress >= NETWORK_RESTRICT_PROGRESS_THRESHOLD
            and confidence >= NETWORK_RESTRICT_CONFIDENCE_THRESHOLD
        ):
            recommended_control = 'NETWORK_RESTRICT'

    if progress < 40 and recommended_control is None:
        return {
            'persisted': False,
            'user': user,
            'current_stage': stage,
            'threat_progress': progress,
            'predicted_vector': vector,
            'prediction_confidence': confidence,
            'response_level': response_level,
            'recommended_control': None,
            'gru_next_action': gru_next_action,
            'gru_risk_probability': round(gru_risk_probability, 6),
            'gru_progress_boost': gru_progress_boost,
            'evidence': evidence,
            'status': 'OBSERVING',
            'control_action': None,
        }

    # Persist structured GRU metadata without DB schema migration.
    gru_meta_payload = {
        'gru_next_action': gru_next_action,
        'gru_risk_probability': round(gru_risk_probability, 6),
        'gru_progress_boost': gru_progress_boost,
    }
    evidence.append(
        'GRU_META::' + json.dumps(gru_meta_payload, ensure_ascii=False)
    )

    row = ThreatPrediction(
        user=user, target_host=target_host, current_stage=stage,
        threat_progress=progress, predicted_vector=vector,
        prediction_confidence=confidence, response_level=response_level,
        recommended_control=recommended_control,
        evidence_json=json.dumps(evidence, ensure_ascii=False),
        source_event_id=source_event_id,
        source_risk_score=float(risk_score or 0),
        sequence_score=float(sequence_score or 0),
        baseline_score=float(baseline_score or 0),
        peer_score=float(peer_score or 0),
        status='PROPOSED' if recommended_control else 'OBSERVING',
    )
    db.add(row); db.commit(); db.refresh(row)

    control_action = None
    auto_control_types = {
        'USB_WRITE_RESTRICT',
        'NETWORK_RESTRICT',
    }

    if (
        AUTO_MICRO_CONTROL_ENABLED
        and recommended_control in auto_control_types
        and bool(str(target_host or '').strip())
        and not _control_active_or_pending(
            db,
            target_host,
            recommended_control,
        )
    ):
        control_action, error = create_control_action(
            db,
            user=user,
            action_type=recommended_control,
            operation='APPLY',
            reason=(
                'Predictive Threat Progression 자동 제어'
                f' · control={recommended_control}'
                f' · stage={stage}'
                f' · progress={progress}'
                f' · confidence={confidence}'
            ),
            target_host=target_host,
            risk_score=int(round(float(risk_score or 0))),
            threat_progress=progress,
            predicted_vector=vector,
            prediction_confidence=confidence,
            requested_by='PREDICTIVE_ENGINE',
        )

        if error is None and control_action:
            row.status = 'CONTROL_QUEUED'
            row.control_action_id = control_action['id']
            row.decision_note = (
                f'조건부 자동 제어 실행 · {recommended_control}'
            )
            db.commit()
            db.refresh(row)

        elif error:
            row.status = 'CONTROL_FAILED'
            row.decision_note = error
            db.commit()
            db.refresh(row)

    return {
        **_serialize(row),
        'persisted': True,
        'control_action': control_action,
        'gru_next_action': gru_next_action,
        'gru_risk_probability': round(gru_risk_probability, 6),
        'gru_progress_boost': gru_progress_boost,
    }


def list_threat_predictions(db, *, user=None, status=None, limit=100):
    q = db.query(ThreatPrediction)
    if user:
        q = q.filter(ThreatPrediction.user == user)
    if status:
        q = q.filter(ThreatPrediction.status == status.upper())
    rows = q.order_by(ThreatPrediction.id.desc()).limit(max(1, min(int(limit or 100), 500))).all()
    return [_serialize(r) for r in rows]


def latest_user_prediction(db, *, user):
    row = db.query(ThreatPrediction).filter(ThreatPrediction.user == user).order_by(ThreatPrediction.id.desc()).first()
    return _serialize(row)


def decide_prediction(db, *, prediction_id, decision, admin_note=None):
    row = db.query(ThreatPrediction).filter(ThreatPrediction.id == prediction_id).first()
    if row is None:
        return None, 'Prediction을 찾을 수 없습니다.'
    if row.status not in {'PROPOSED','OBSERVING'}:
        return None, f'현재 상태에서는 결정할 수 없습니다: {row.status}'

    decision = str(decision or '').upper().strip()
    if decision == 'REJECT':
        row.status = 'REJECTED'; row.decision_note = admin_note
        db.commit(); db.refresh(row)
        return _serialize(row), None
    if decision != 'APPROVE':
        return None, 'decision은 APPROVE 또는 REJECT여야 합니다.'

    executable_controls = {
        'USB_WRITE_RESTRICT',
        'NETWORK_RESTRICT',
    }

    if row.recommended_control not in executable_controls:
        row.status = 'APPROVED'
        row.decision_note = admin_note or '승인됨 - 실행 가능한 실제 제어 없음'
        db.commit()
        db.refresh(row)
        return _serialize(row), None

    if not str(row.target_host or '').strip():
        return None, (
            '대상 Host가 없는 Prediction에는 실제 엔드포인트 제어를 실행할 수 없습니다.'
        )

    if _control_active_or_pending(
        db,
        row.target_host,
        row.recommended_control,
    ):
        row.status = 'APPROVED'
        row.decision_note = (
            f'동일 Host의 {row.recommended_control} 제어가 이미 적용 또는 대기 중'
        )
        db.commit()
        db.refresh(row)
        return _serialize(row), None

    action, error = create_control_action(
        db,
        user=row.user,
        action_type=row.recommended_control,
        operation='APPLY',
        reason=(
            'Predictive Threat Progression 관리자 승인'
            f' · Prediction #{row.id}'
            f' · control={row.recommended_control}'
        ),
        target_host=row.target_host,
        risk_score=int(round(float(row.source_risk_score or 0))),
        threat_progress=row.threat_progress,
        predicted_vector=row.predicted_vector,
        prediction_confidence=row.prediction_confidence,
        requested_by='PREDICTION_ADMIN',
        admin_note=admin_note,
    )
    if error:
        return None, error

    row.status = 'CONTROL_QUEUED'; row.control_action_id = action['id']; row.decision_note = admin_note
    db.commit(); db.refresh(row)
    return _serialize(row), None
