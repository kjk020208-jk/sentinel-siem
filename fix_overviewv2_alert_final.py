from pathlib import Path
import re, shutil, sys

ROOT = Path.cwd()
APP = ROOT / 'sentinel-react-frontend' / 'src' / 'App.jsx'

if not APP.exists():
    print('[ERROR] App.jsx not found')
    sys.exit(1)

backup = APP.with_name(APP.name + '.before_overviewv2_alert_fix')
if not backup.exists():
    shutil.copy2(APP, backup)
    print('[BACKUP]', backup.relative_to(ROOT))

app = APP.read_text(encoding='utf-8')

m = re.search(r'function\s+OverviewV2\s*\(([^)]*)\)\s*\{', app)
if not m:
    raise RuntimeError('OverviewV2 function not found')

start = m.start()
mnext = re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(', app[m.end():])
end = m.end() + mnext.start() if mnext else len(app)
component = app[start:end]

# prevent duplicate application
if 'overview-v2-live-alert' in component:
    print('[OK] OverviewV2 alert already present')
else:
    brace = component.find('{')
    component = component[:brace+1] + "\n  const[overviewV2AckEventId,setOverviewV2AckEventId]=useState('')" + component[brace+1:]

    lm = re.search(r'\n\s*const\s+latest\s*=\s*events\[0\]', component)
    if not lm:
        raise RuntimeError('OverviewV2 latest=events[0] anchor not found')

    logic = (
        "\n  const latestRiskEventForAlertV2=events.find(e=>['HIGH','CRITICAL'].includes(String(e.risk_level||'').toUpperCase()))||null"
        "\n  const latestRiskAlertIdV2=String(latestRiskEventForAlertV2?.id??latestRiskEventForAlertV2?.event_id??'')"
        "\n  useEffect(()=>{if(latestRiskAlertIdV2)setOverviewV2AckEventId('')},[latestRiskAlertIdV2])\n"
    )
    component = component[:lm.end()] + logic + component[lm.end():]

    ret = re.search(r'return\s*\(\s*<>', component)
    if not ret:
        raise RuntimeError('OverviewV2 return fragment not found')

    alert = '''
      {latestRiskEventForAlertV2&&latestRiskAlertIdV2!==overviewV2AckEventId&&(
        <div className="critical-alert overview-v2-live-alert">
          <div className="live-alert-top">
            <div className="live-alert-title">LIVE SECURITY ALERT</div>
            <div className="live-alert-time">{fmt(latestRiskEventForAlertV2.timestamp||latestRiskEventForAlertV2.created_at)}</div>
          </div>
          <div className="live-alert-main">
            {['web_upload','email_send','external_transfer'].includes(String(latestRiskEventForAlertV2.event_type||'').toLowerCase())
              ? '\uB300\uC678\uBE44 \uC678\uBD80 \uC804\uC1A1 \uC2DC\uB3C4 \uAC10\uC9C0'
              : `${String(latestRiskEventForAlertV2.risk_level||'HIGH').toUpperCase()} \uBCF4\uC548 \uC774\uBCA4\uD2B8 \uAC10\uC9C0`}
          </div>
          <div className="live-alert-meta">
            {'\uC0AC\uC6A9\uC790'} {latestRiskEventForAlertV2.user||'-'} {'\u00B7'}
            {' '}{koEvent(latestRiskEventForAlertV2.event_type)} {'\u00B7'}
            {' '}Risk {num(latestRiskEventForAlertV2.risk_score).toFixed(2)} {'\u00B7'}
            {' '}Event #{latestRiskEventForAlertV2.id||latestRiskEventForAlertV2.event_id}
            {latestRiskEventForAlertV2.file_name&&<> {'\u00B7'} {'\uD30C\uC77C'} {latestRiskEventForAlertV2.file_name}</>}
            {latestRiskEventForAlertV2.process_name&&<> {'\u00B7'} {'\uD504\uB85C\uC138\uC2A4'} {latestRiskEventForAlertV2.process_name}</>}
          </div>
          <div className="alert-actions">
            <button className="btn danger" onClick={()=>setPage('events')}>{'\uC774\uBCA4\uD2B8 \uC0C1\uC138 \uD655\uC778'}</button>
            <button className="btn ghost" onClick={()=>setOverviewV2AckEventId(latestRiskAlertIdV2)}>{'\uD655\uC778'}</button>
          </div>
        </div>
      )}
'''
    component = component[:ret.end()] + alert + component[ret.end():]

    app = app[:start] + component + app[end:]

m2 = re.search(r'function\s+OverviewV2\s*\(([^)]*)\)\s*\{', app)
start2 = m2.start()
mnext2 = re.search(r'\nfunction\s+[A-Za-z0-9_]+\s*\(', app[m2.end():])
end2 = m2.end() + mnext2.start() if mnext2 else len(app)
scope = app[start2:end2]

required = ['overviewV2AckEventId','latestRiskEventForAlertV2','overview-v2-live-alert']
missing = [x for x in required if x not in scope]
if missing:
    raise RuntimeError('VERIFY FAILED in OverviewV2: ' + ', '.join(missing))

APP.write_text(app, encoding='utf-8')
print('[FOUND] OverviewV2')
print('[VERIFY OK] alert is inside OverviewV2')
print('[WRITE]', APP.relative_to(ROOT))