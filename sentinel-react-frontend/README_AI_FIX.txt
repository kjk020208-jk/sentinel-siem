SENTINEL React v7 - AI functional fix

Authoritative source: uploaded dashboard/app(2).py

Fixes:
- Event AI renders exact Streamlit response fields:
  summary, threat_scenario, evidence, recommendations
- Incident AI renders exact Streamlit response fields:
  incident_summary, threat_scenario, confirmed_facts, uncertainties,
  attack_flow_analysis, mitre_analysis, key_evidence,
  investigation_priorities, response_recommendations, analyst_caution
- AI API errors are displayed directly below the clicked AI button.
- Full API response is retained; JSON/string AI payloads are safely unwrapped.
- Raw AI response fallback is available when a response shape is unexpected.
- Related event AI area matches the Streamlit section order more closely.

Run:
  npm.cmd install
  npm.cmd run dev
