from pathlib import Path
import sys, shutil

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'

if not APP.exists():
    print('[ERROR] App.jsx not found')
    sys.exit(1)

backup = APP.with_name(APP.name + '.before_alert_text_encoding_fix')
if not backup.exists():
    shutil.copy2(APP, backup)
    print('[BACKUP]', backup.relative_to(ROOT))

app = APP.read_text(encoding='utf-8')

start_marker = '      {latestRiskEventForAlert&&latestRiskAlertId!==overviewAckEventId&&('
end_marker = '      )}'

start = app.find(start_marker)
if start < 0:
    raise RuntimeError('alert block start not found')

end = app.find(end_marker, start)
if end < 0:
    raise RuntimeError('alert block end not found')
end += len(end_marker)

block = r'''      {latestRiskEventForAlert&&latestRiskAlertId!==overviewAckEventId&&(
        <div className="critical-alert overview-live-critical-alert">
          <div className="live-alert-top">
            <div className="live-alert-title">LIVE SECURITY ALERT</div>
            <div className="live-alert-time">
              {fmt(latestRiskEventForAlert.timestamp||latestRiskEventForAlert.created_at)}
            </div>
          </div>

          <div className="live-alert-main">
            {['web_upload','email_send','external_transfer'].includes(
              String(latestRiskEventForAlert.event_type||'').toLowerCase()
            )
              ? '\uB300\uC678\uBE44 \uC678\uBD80 \uC804\uC1A1 \uC2DC\uB3C4 \uAC10\uC9C0'
              : `${String(latestRiskEventForAlert.risk_level||'HIGH').toUpperCase()} \uBCF4\uC548 \uC774\uBCA4\uD2B8 \uAC10\uC9C0`}
          </div>

          <div className="live-alert-meta">
            {'\uC0AC\uC6A9\uC790'} {latestRiskEventForAlert.user||'-'} ·
            {' '}{koEvent(latestRiskEventForAlert.event_type)} ·
            {' '}Risk {num(latestRiskEventForAlert.risk_score).toFixed(2)} ·
            {' '}Event #{latestRiskEventForAlert.id||latestRiskEventForAlert.event_id}
            {latestRiskEventForAlert.file_name&&<> · {'\uD30C\uC77C'} {latestRiskEventForAlert.file_name}</>}
            {latestRiskEventForAlert.process_name&&<> · {'\uD504\uB85C\uC138\uC2A4'} {latestRiskEventForAlert.process_name}</>}
          </div>

          <div className="alert-actions">
            <button className="btn danger" onClick={()=>setPage('events')}>
              {'\uC774\uBCA4\uD2B8 \uC0C1\uC138 \uD655\uC778'}
            </button>
            <button
              className="btn ghost"
              onClick={()=>setOverviewAckEventId(latestRiskAlertId)}
            >
              {'\uD655\uC778'}
            </button>
          </div>
        </div>
      )}'''

app = app[:start] + block + app[end:]

required = [
    'overview-live-critical-alert',
    '\\uB300\\uC678\\uBE44',
    '\\uC774\\uBCA4\\uD2B8 \\uC0C1\\uC138 \\uD655\\uC778',
]
missing = [x for x in required if x not in app]
if missing:
    raise RuntimeError('VERIFY FAILED: ' + ', '.join(missing))

APP.write_text(app, encoding='utf-8')
print('[VERIFY OK] alert text encoding fixed')
print('[WRITE]', APP.relative_to(ROOT))