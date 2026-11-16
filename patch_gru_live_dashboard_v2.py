
from pathlib import Path
import shutil
import py_compile
import sys

ROOT = Path.cwd()
AUTH = ROOT / "server" / "auth.py"
APP = ROOT / "sentinel-react-frontend" / "src" / "App.jsx"

for p in (AUTH, APP):
    if not p.exists():
        print(f"[ERROR] missing: {p}")
        sys.exit(1)

for p in (AUTH, APP):
    b = p.with_name(p.name + ".before_gru_live_dashboard_v2")
    if not b.exists():
        shutil.copy2(p, b)
        print(f"[BACKUP] {b.relative_to(ROOT)}")

# 1) Restore normal session auth for GRU API.
auth = AUTH.read_text(encoding="utf-8")
bridge = (
    '        # GRU next-action API: skip session-cookie auth here.\n'
    '        # main.py still enforces SENTINEL Basic admin authentication.\n'
    '        if path.startswith("/next-action/predict/") and method == "GET":\n'
    '            return await call_next(request)\n\n'
)
if bridge in auth:
    auth = auth.replace(bridge, "", 1)
    AUTH.write_text(auth, encoding="utf-8")
    print("[PATCH] GRU API now uses normal dashboard session auth")
else:
    print("[SKIP] GRU session-auth bypass not present")

py_compile.compile(str(AUTH), doraise=True)
print("[COMPILE OK] server/auth.py")

# 2) Frontend live GRU polling.
app = APP.read_text(encoding="utf-8")
start = app.find("function SoarControlPage(){")
if start < 0:
    raise RuntimeError("SoarControlPage not found")

state_anchor = '  const[predictions,setPredictions]=useState([])\n'
if 'const[liveGru,setLiveGru]' not in app[start:]:
    if state_anchor not in app[start:]:
        raise RuntimeError("predictions state anchor not found")
    app = app.replace(
        state_anchor,
        state_anchor + '  const[liveGru,setLiveGru]=useState(null)\n',
        1,
    )
    print("[PATCH] live GRU state added")

old_load = """  const load=async()=>{
    try{
      const[controlData,predictionData]=await Promise.all([
        call('/response-controls?limit=100'),
        call('/threat-predictions?limit=100')
      ])
      setRows(arr(controlData,['items','value','response_controls']))
      setPredictions(arr(predictionData,['items','value','predictions','threat_predictions']))
      setErr('')
    }catch(e){
      setErr(e.message)
    }
  }
"""
new_load = """  const load=async()=>{
    try{
      const[controlData,predictionData]=await Promise.all([
        call('/response-controls?limit=100'),
        call('/threat-predictions?limit=100')
      ])
      setRows(arr(controlData,['items','value','response_controls']))
      setPredictions(arr(predictionData,['items','value','predictions','threat_predictions']))
      setErr('')
    }catch(e){
      setErr(e.message)
    }

    try{
      const gruData=await call('/next-action/predict/siem_demo?top_k=3')
      setLiveGru(gruData?.available?gruData:null)
    }catch(e){
      setLiveGru(null)
    }
  }
"""
if "call('/next-action/predict/siem_demo?top_k=3')" not in app[start:]:
    if old_load not in app[start:]:
        raise RuntimeError("SoarControlPage load block not found")
    app = app.replace(old_load, new_load, 1)
    print("[PATCH] live GRU polling added")

old_derived = """  const latestGruPrediction=[...predictions]
    .sort((a,b)=>num(b.id)-num(a.id))
    .find(p=>p?.gru_next_action?.available)||null
  const latestGru=latestGruPrediction?.gru_next_action||{}
  const latestGruTop3=Array.isArray(latestGru?.predictions)?latestGru.predictions:[]
  const latestGruTop1=latestGruTop3[0]||null
"""
new_derived = """  const latestPersistedGruPrediction=[...predictions]
    .sort((a,b)=>num(b.id)-num(a.id))
    .find(p=>p?.gru_next_action?.available)||null

  const latestThreatPrediction=[...predictions]
    .sort((a,b)=>num(b.id)-num(a.id))[0]||null

  const latestGru=liveGru?.available
    ? liveGru
    : (latestPersistedGruPrediction?.gru_next_action||{})

  const latestGruTop3=Array.isArray(latestGru?.predictions)?latestGru.predictions:[]
  const latestGruTop1=latestGruTop3[0]||null

  const gruRiskActions=new Set([
    'LOGIN_FAILURE','SENSITIVE_FILE_ACCESS','MASS_FILE_ACCESS',
    'POWERSHELL','SCRIPT_EXECUTION','ARCHIVE_CREATE',
    'USB_COPY','EXTERNAL_TRANSFER','WEB_UPLOAD','EMAIL_SEND'
  ])

  const liveGruRiskProbability=latestGruTop3.reduce((best,p)=>{
    const action=String(p?.action||'').toUpperCase()
    const probability=num(p?.probability)
    return gruRiskActions.has(action)?Math.max(best,probability):best
  },0)

  const liveGruProgressBoost=
    liveGruRiskProbability>=0.60?5:
    liveGruRiskProbability>=0.35?3:
    liveGruRiskProbability>=0.20?1:0

  const latestGruPrediction=latestThreatPrediction
"""
if 'const latestPersistedGruPrediction=' not in app[start:]:
    if old_derived not in app[start:]:
        raise RuntimeError("persisted GRU derived block not found")
    app = app.replace(old_derived, new_derived, 1)
    print("[PATCH] live GRU merged with latest Threat Prediction")

app = app.replace(
    '      {latestGruPrediction\n        ? <>\n',
    '      {latestGru?.available\n        ? <>\n',
    1,
)
app = app.replace(
    "                  사용자 {latestGruPrediction.user||'-'} · 최근 행동 {latestGru.sequence_length_used??'-'}개 기반\n",
    "                  사용자 {latestGru.user||latestGruPrediction?.user||'-'} · 최근 행동 {latestGru.sequence_length_used??'-'}개 기반\n",
    1,
)
app = app.replace(
    "<strong>{latestGruPrediction.prediction_confidence==null?'-':`${latestGruPrediction.prediction_confidence}%`}</strong>",
    "<strong>{latestGruPrediction?.prediction_confidence==null?'-':`${latestGruPrediction.prediction_confidence}%`}</strong>",
    1,
)
app = app.replace(
    "<strong>{latestGruPrediction.gru_risk_probability==null?'-':`${(num(latestGruPrediction.gru_risk_probability)*100).toFixed(2)}%`}</strong>",
    "<strong>{`${(liveGruRiskProbability*100).toFixed(2)}%`}</strong>",
    1,
)
app = app.replace(
    "<strong>{`+${num(latestGruPrediction.gru_progress_boost)}`}</strong>",
    "<strong>{`+${liveGruProgressBoost}`}</strong>",
    1,
)
app = app.replace(
    "<strong>{latestGruPrediction.threat_progress==null?'-':`${latestGruPrediction.threat_progress}%`}</strong>",
    "<strong>{latestGruPrediction?.threat_progress==null?'-':`${latestGruPrediction.threat_progress}%`}</strong>",
    1,
)
app = app.replace(
    "<small>{latestGruPrediction.response_level||'-'}</small>",
    "<small>{latestGruPrediction?.response_level||'현재 저장된 Threat Progression 없음'}</small>",
    1,
)
app = app.replace(
    "            GRU Next-Action 결과가 저장된 Prediction이 아직 없습니다. 새 이벤트가 들어오면 최신 예측이 자동 표시됩니다.\n",
    "            최근 행동이 3개 이상 쌓이면 GRU 실시간 다음 행동 예측이 자동 표시됩니다.\n",
    1,
)

APP.write_text(app, encoding="utf-8")
print("[WRITE] sentinel-react-frontend/src/App.jsx")
print()
print("=" * 78)
print("SENTINEL GRU Live Dashboard v2 installed")
print("=" * 78)
print("- polls /next-action/predict/siem_demo?top_k=3 every 3 seconds")
print("- GRU card works even when Threat Progress < 40")
print("- latest persisted Threat Progression is merged when available")
print("- normal dashboard session authentication restored for GRU API")
print()
print("Next:")
print("  cd sentinel-react-frontend")
print("  npm.cmd run build")
