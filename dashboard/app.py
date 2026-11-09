import streamlit as st
import pandas as pd
import requests
import plotly.graph_objects as go
import re
from datetime import datetime
from time import perf_counter


# =========================================================
# 기본 설정
# =========================================================

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="SENTINEL | 내부자 위협 보안 관제",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# CSS
# =========================================================

st.markdown("""
<style>

.stApp {
    background:
        radial-gradient(
            circle at 82% -10%,
            rgba(30, 64, 175, 0.08),
            transparent 30%
        ),
        #080c14;
    color: #d8dee9;
}

.block-container {
    max-width: 1600px;
    padding-top: 1.45rem;
    padding-bottom: 4rem;
    padding-left: 2.2rem;
    padding-right: 2.2rem;
}

header[data-testid="stHeader"] {
    background: transparent;
}

#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

html, body, [class*="css"] {
    font-family:
        Pretendard,
        "Noto Sans KR",
        "Segoe UI",
        sans-serif;
}


/* ======================================================
   사이드바
   ====================================================== */

section[data-testid="stSidebar"] {
    background: #0b1019;
    border-right: 1px solid #1d2635;
}

section[data-testid="stSidebar"] > div {
    padding-top: 1.2rem;
}

.sidebar-brand {
    padding: 8px 4px 19px 4px;
}

.sidebar-brand-name {
    font-size: 21px;
    font-weight: 800;
    letter-spacing: 0.12em;
    color: #f3f6fa;
}

.sidebar-brand-sub {
    font-size: 10px;
    color: #64748b;
    margin-top: 5px;
}

.side-section {
    color: #536176;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.10em;
    margin-top: 18px;
    margin-bottom: 8px;
}

.engine-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11px;
    padding: 6px 2px;
    color: #8e9bad;
    border-bottom: 1px solid #151d29;
}

.engine-online {
    color: #35d07f;
    font-size: 9px;
}

section[data-testid="stSidebar"] .stButton > button {
    width: 100%;
}


/* ======================================================
   상단 헤더
   ====================================================== */

.soc-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding-bottom: 18px;
    margin-bottom: 20px;
    border-bottom: 1px solid #1c2634;
}

.soc-title {
    color: #f1f5f9;
    font-size: 25px;
    font-weight: 700;
    letter-spacing: -0.025em;
}

.soc-subtitle {
    color: #66758a;
    font-size: 11px;
    margin-top: 5px;
}

.system-online {
    display: inline-block;
    border: 1px solid #1e3b32;
    background: #0c1916;
    color: #51d691;
    font-size: 10px;
    font-weight: 700;
    padding: 7px 11px;
    border-radius: 3px;
}


/* ======================================================
   섹션
   ====================================================== */

.section-header {
    margin-top: 27px;
    margin-bottom: 13px;
    display: flex;
    align-items: center;
    gap: 10px;
}

.section-title {
    color: #dbe3ed;
    font-size: 13px;
    font-weight: 700;
    white-space: nowrap;
}

.section-line {
    height: 1px;
    flex-grow: 1;
    background: #1b2532;
}


/* ======================================================
   KPI
   ====================================================== */

.kpi-card {
    background: #0d131d;
    border: 1px solid #1b2635;
    border-radius: 5px;
    padding: 17px 18px 15px 18px;
    min-height: 105px;
}

.kpi-label {
    color: #69788d;
    font-size: 10px;
    font-weight: 700;
    margin-bottom: 10px;
}

.kpi-value {
    color: #edf2f7;
    font-size: 29px;
    line-height: 1;
    font-weight: 650;
}

.kpi-foot {
    color: #536176;
    font-size: 10px;
    margin-top: 9px;
}

.kpi-warning {
    color: #f5a742;
}

.kpi-danger {
    color: #ff5c68;
}


/* ======================================================
   SOC 패널
   ====================================================== */

.soc-panel {
    background: #0d131d;
    border: 1px solid #1b2635;
    border-radius: 5px;
    padding: 18px 20px 19px 20px;
    min-height: 300px;
}

.panel-title {
    color: #d5dde7;
    font-size: 12px;
    font-weight: 700;
}

.panel-sub {
    color: #526176;
    font-size: 10px;
    margin-top: 4px;
    margin-bottom: 21px;
}

.risk-row {
    display: grid;
    grid-template-columns: 105px 52px 1fr;
    gap: 10px;
    align-items: center;
    margin: 15px 0;
}

.risk-user {
    color: #aeb9c7;
    font-size: 11px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.risk-number {
    color: #e1e7ef;
    font-family: Consolas, monospace;
    font-size: 11px;
    text-align: right;
}

.bar-track {
    width: 100%;
    height: 7px;
    background: #182230;
    border-radius: 2px;
    overflow: hidden;
}

.bar-fill {
    height: 100%;
    background: #3b82f6;
}

.severity-row {
    display: grid;
    grid-template-columns: 80px 55px 1fr 48px;
    gap: 9px;
    align-items: center;
    margin: 15px 0;
}

.severity-name {
    font-size: 10px;
    font-weight: 700;
}

.severity-count {
    font-size: 12px;
    font-family: Consolas, monospace;
    color: #e0e6ee;
    text-align: right;
}

.severity-percent {
    font-size: 9px;
    color: #637287;
    text-align: right;
}

.fill-critical {
    background: #ef4444;
}

.fill-high {
    background: #f59e0b;
}

.fill-medium {
    background: #eab308;
}

.fill-low {
    background: #22c55e;
}

.text-critical {
    color: #ff5964;
}

.text-high {
    color: #f59e0b;
}

.text-medium {
    color: #eab308;
}

.text-low {
    color: #3fcf8e;
}


/* ======================================================
   사건 분석
   ====================================================== */

.incident-header {
    background: #0d131d;
    border: 1px solid #263244;
    border-left: 3px solid #64748b;
    border-radius: 4px;
    padding: 17px 20px;
    margin: 8px 0 16px 0;
}

.incident-critical {
    border-left-color: #ef4444;
}

.incident-high {
    border-left-color: #f59e0b;
}

.incident-medium {
    border-left-color: #eab308;
}

.incident-low {
    border-left-color: #22c55e;
}

.incident-top {
    color: #77869b;
    font-size: 10px;
    font-weight: 700;
}

.incident-name {
    color: #edf2f7;
    font-size: 20px;
    font-weight: 650;
    margin-top: 6px;
}

.risk-critical {
    color: #ff5964;
}

.risk-high {
    color: #f59e0b;
}

.risk-medium {
    color: #eab308;
}

.risk-low {
    color: #3fcf8e;
}

.detail-box {
    background: #0b111a;
    border: 1px solid #192433;
    border-radius: 4px;
    padding: 13px 15px;
    min-height: 78px;
    margin-bottom: 8px;
}

.detail-label {
    color: #5f6e82;
    font-size: 9px;
    font-weight: 700;
    margin-bottom: 7px;
}

.detail-value {
    color: #d9e0e8;
    font-size: 13px;
    word-break: break-all;
}


/* ======================================================
   탐지 근거
   ====================================================== */

.evidence-item {
    display: flex;
    align-items: flex-start;
    gap: 13px;
    background: #0b111a;
    border-bottom: 1px solid #19222e;
    padding: 11px 13px;
    color: #b7c0cd;
    font-size: 12px;
}

.evidence-number {
    color: #52657d;
    font-size: 10px;
    font-family: Consolas, monospace;
    min-width: 30px;
}


/* ======================================================
   AI
   ====================================================== */

.ai-shell {
    background: #0c121c;
    border: 1px solid #263449;
    border-radius: 5px;
    padding: 20px 22px;
    margin-top: 12px;
}

.ai-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #1d2938;
    padding-bottom: 12px;
    margin-bottom: 17px;
}

.ai-title {
    color: #e5eaf1;
    font-size: 13px;
    font-weight: 750;
}

.ai-model {
    color: #64748b;
    font-size: 9px;
}

.ai-section-label {
    color: #718198;
    font-size: 10px;
    font-weight: 750;
    margin-top: 15px;
    margin-bottom: 6px;
}

.ai-text {
    color: #c5ced9;
    font-size: 12px;
    line-height: 1.75;
}

.recommendation {
    background: #101823;
    border-left: 2px solid #3b82f6;
    padding: 10px 12px;
    margin: 7px 0;
    color: #bdc8d6;
    font-size: 12px;
    line-height: 1.6;
}


/* ======================================================
   사용자 분석
   ====================================================== */

.user-profile {
    background: #0d131d;
    border: 1px solid #1b2635;
    border-left: 3px solid #3b82f6;
    border-radius: 5px;
    padding: 18px 20px;
    margin-bottom: 16px;
}

.user-profile-label {
    color: #64748b;
    font-size: 9px;
    font-weight: 700;
}

.user-profile-name {
    color: #edf2f7;
    font-size: 21px;
    font-weight: 650;
    margin-top: 5px;
}



/* ======================================================
   Adaptive Personal UEBA
   ====================================================== */

.baseline-summary {
    background: #0d131d;
    border: 1px solid #1b2635;
    border-left: 3px solid #3b82f6;
    border-radius: 5px;
    padding: 18px 20px;
    margin-bottom: 14px;
}

.baseline-top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 20px;
}

.baseline-user {
    color: #edf2f7;
    font-size: 21px;
    font-weight: 650;
}

.baseline-meta {
    color: #64748b;
    font-size: 10px;
    margin-top: 6px;
}

.baseline-badge {
    display: inline-block;
    padding: 6px 10px;
    border: 1px solid #29405e;
    background: #101b2a;
    color: #8ab8ff;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 750;
    white-space: nowrap;
}

.baseline-card {
    background: #0d131d;
    border: 1px solid #1b2635;
    border-radius: 5px;
    padding: 16px 17px;
    min-height: 112px;
}

.baseline-card-label {
    color: #64748b;
    font-size: 9px;
    font-weight: 750;
    margin-bottom: 9px;
}

.baseline-card-value {
    color: #e4eaf1;
    font-size: 15px;
    font-weight: 650;
    line-height: 1.45;
    word-break: break-word;
}

.baseline-card-foot {
    color: #4f5e72;
    font-size: 9px;
    margin-top: 7px;
}

.confidence-track {
    width: 100%;
    height: 7px;
    background: #182230;
    border-radius: 2px;
    overflow: hidden;
    margin-top: 10px;
}

.confidence-fill {
    height: 100%;
    background: #3b82f6;
}

.learning-note {
    background: #0b111a;
    border: 1px solid #1b2635;
    border-left: 2px solid #3b82f6;
    padding: 11px 13px;
    color: #8493a7;
    font-size: 10px;
    line-height: 1.65;
    margin-top: 10px;
}

/* ======================================================
   Streamlit
   ====================================================== */

div[data-testid="stDataFrame"] {
    border: 1px solid #1b2635;
    border-radius: 4px;
}

div[data-baseweb="select"] > div {
    background-color: #0c121b;
    border-color: #263244;
}

.stButton > button {
    background: #121b28;
    color: #cdd6e1;
    border: 1px solid #2a384b;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 650;
    min-height: 38px;
    transition: 0.15s;
}

.stButton > button:hover {
    background: #182538;
    border-color: #3b82f6;
    color: #ffffff;
}

div[data-testid="stAlert"] {
    border-radius: 4px;
}



/* ======================================================
   Dynamic User Risk
   ====================================================== */

.dynamic-risk-shell {
    background:#0d131d;
    border:1px solid #1b2635;
    border-left:3px solid #eab308;
    border-radius:5px;
    padding:19px 20px;
    margin-bottom:14px;
}

.dynamic-risk-top {
    display:flex;
    justify-content:space-between;
    align-items:flex-start;
    gap:20px;
}

.dynamic-risk-label {
    color:#64748b;
    font-size:9px;
    font-weight:750;
    letter-spacing:.05em;
}

.dynamic-risk-score {
    color:#edf2f7;
    font-size:34px;
    line-height:1;
    font-weight:700;
    margin-top:7px;
}

.dynamic-risk-meta {
    color:#64748b;
    font-size:10px;
    margin-top:8px;
    line-height:1.6;
}

.dynamic-risk-badge {
    display:inline-block;
    padding:7px 11px;
    border-radius:3px;
    font-size:10px;
    font-weight:800;
    white-space:nowrap;
}

.dynamic-badge-critical {
    color:#ff5964;
    background:#241013;
    border:1px solid #5c2229;
}

.dynamic-badge-high {
    color:#f59e0b;
    background:#21180b;
    border:1px solid #5b4318;
}

.dynamic-badge-medium {
    color:#eab308;
    background:#211d08;
    border:1px solid #554b17;
}

.dynamic-badge-low {
    color:#3fcf8e;
    background:#0c1916;
    border:1px solid #1e3b32;
}

.dynamic-track {
    width:100%;
    height:9px;
    background:#182230;
    border-radius:2px;
    overflow:hidden;
    margin-top:16px;
}

.dynamic-fill {
    height:100%;
    background:#eab308;
}

.dynamic-contributor {
    background:#0b111a;
    border:1px solid #192433;
    border-radius:4px;
    padding:12px 14px;
    margin-bottom:8px;
}

.dynamic-contributor-top {
    display:flex;
    justify-content:space-between;
    gap:14px;
    align-items:center;
}

.dynamic-contributor-type {
    color:#dbe3ed;
    font-size:11px;
    font-weight:700;
}

.dynamic-contributor-score {
    color:#eab308;
    font-size:12px;
    font-family:Consolas,monospace;
}

.dynamic-contributor-meta {
    color:#5f6e82;
    font-size:9px;
    margin-top:6px;
    line-height:1.55;
}


/* Adaptive UEBA 비교 시연 */
.adaptive-demo-shell {background:#0b111a;border:1px solid #1b2635;border-radius:5px;padding:18px 20px;margin-top:8px;}
.adaptive-demo-head {color:#dbe3ed;font-size:13px;font-weight:750;margin-bottom:5px;}
.adaptive-demo-sub {color:#64748b;font-size:10px;line-height:1.6;margin-bottom:14px;}
.adaptive-demo-card {background:#0d131d;border:1px solid #1b2635;border-radius:5px;padding:17px 18px;min-height:255px;}
.adaptive-demo-office {border-left:3px solid #f59e0b;}
.adaptive-demo-flex {border-left:3px solid #3b82f6;}
.adaptive-demo-type {color:#64748b;font-size:9px;font-weight:750;margin-bottom:5px;}
.adaptive-demo-user {color:#edf2f7;font-size:18px;font-weight:700;margin-bottom:13px;}
.adaptive-demo-row {display:flex;justify-content:space-between;gap:14px;border-top:1px solid #182230;padding:9px 0;font-size:11px;}
.adaptive-demo-label {color:#64748b;}
.adaptive-demo-value {color:#dbe3ed;font-family:Consolas,monospace;text-align:right;}
.adaptive-demo-good {color:#3fcf8e;}
.adaptive-demo-warn {color:#f59e0b;}
.adaptive-demo-reason {background:#101823;border-left:2px solid #3b82f6;padding:10px 12px;margin-top:12px;color:#aeb9c7;font-size:10px;line-height:1.65;}


/* ======================================================
   Incident Correlation / Attack Storyline
   ====================================================== */

.incident-correlation-shell {
    background: #0d131d;
    border: 1px solid #263244;
    border-left: 3px solid #ef4444;
    border-radius: 5px;
    padding: 19px 20px;
    margin: 8px 0 14px 0;
}

.incident-correlation-top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 20px;
}

.incident-correlation-id {
    color: #64748b;
    font-size: 9px;
    font-weight: 750;
    letter-spacing: .05em;
}

.incident-correlation-title {
    color: #edf2f7;
    font-size: 20px;
    font-weight: 700;
    margin-top: 6px;
}

.incident-correlation-meta {
    color: #64748b;
    font-size: 10px;
    margin-top: 7px;
    line-height: 1.6;
}

.incident-status-badge {
    display: inline-block;
    padding: 7px 11px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 800;
    white-space: nowrap;
    color: #ff5964;
    background: #241013;
    border: 1px solid #5c2229;
}

.storyline-shell {
    background: #0b111a;
    border: 1px solid #1b2635;
    border-radius: 5px;
    padding: 18px 20px;
    margin-top: 8px;
}

.storyline-step {
    display: grid;
    grid-template-columns: 44px 1fr 105px;
    gap: 14px;
    align-items: center;
    background: #0d131d;
    border: 1px solid #192433;
    border-left: 2px solid #3b82f6;
    border-radius: 4px;
    padding: 13px 15px;
}

.storyline-index {
    color: #8ab8ff;
    font-family: Consolas, monospace;
    font-size: 11px;
    font-weight: 750;
}

.storyline-name {
    color: #dbe3ed;
    font-size: 12px;
    font-weight: 700;
}

.storyline-detail {
    color: #64748b;
    font-size: 9px;
    margin-top: 5px;
    line-height: 1.55;
}

.storyline-risk {
    text-align: right;
    font-family: Consolas, monospace;
    font-size: 10px;
    color: #aeb9c7;
}

.storyline-arrow {
    color: #3b82f6;
    font-size: 17px;
    text-align: center;
    line-height: 1;
    padding: 5px 0;
}

.incident-kpi {
    background: #0d131d;
    border: 1px solid #1b2635;
    border-radius: 5px;
    padding: 14px 16px;
    min-height: 92px;
}

.incident-kpi-label {
    color: #64748b;
    font-size: 9px;
    font-weight: 750;
    margin-bottom: 8px;
}

.incident-kpi-value {
    color: #edf2f7;
    font-size: 22px;
    font-weight: 700;
}

.incident-kpi-foot {
    color: #526176;
    font-size: 9px;
    margin-top: 6px;
}


.mitre-row {
    margin-top: 7px;
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
}
.mitre-badge {
    display: inline-block;
    padding: 3px 7px;
    border-radius: 3px;
    border: 1px solid #315a8d;
    background: #101d2e;
    color: #8ab8ff;
    font-family: Consolas, monospace;
    font-size: 9px;
    font-weight: 800;
}
.mitre-tactic {
    display: inline-block;
    padding: 3px 7px;
    border-radius: 3px;
    border: 1px solid #263244;
    background: #111823;
    color: #9aa8ba;
    font-size: 9px;
}
.mitre-confidence {
    display: inline-block;
    padding: 3px 7px;
    border-radius: 3px;
    border: 1px solid #3a4657;
    color: #aeb9c7;
    font-size: 9px;
}

/* ======================================================
   Response Playbook / SOAR-lite
   ====================================================== */

.playbook-shell {
    background:#0d131d;
    border:1px solid #263244;
    border-left:3px solid #3b82f6;
    border-radius:5px;
    padding:18px 20px;
    margin-top:8px;
    margin-bottom:14px;
}

.playbook-top {
    display:flex;
    justify-content:space-between;
    gap:20px;
    align-items:flex-start;
}

.playbook-name {
    color:#edf2f7;
    font-size:17px;
    font-weight:700;
}

.playbook-meta {
    color:#64748b;
    font-size:10px;
    margin-top:6px;
    line-height:1.6;
}

.playbook-status {
    display:inline-block;
    padding:6px 9px;
    border:1px solid #315a8d;
    background:#101d2e;
    color:#8ab8ff;
    border-radius:3px;
    font-size:9px;
    font-weight:800;
}

.playbook-progress-track {
    width:100%;
    height:8px;
    background:#182230;
    border-radius:2px;
    overflow:hidden;
    margin-top:14px;
}

.playbook-progress-fill {
    height:100%;
    background:#3b82f6;
}

.playbook-step-card {
    background:#0b111a;
    border:1px solid #192433;
    border-radius:4px;
    padding:13px 15px;
    margin:8px 0;
}

.playbook-step-title {
    color:#dbe3ed;
    font-size:12px;
    font-weight:700;
}

.playbook-step-desc {
    color:#64748b;
    font-size:10px;
    line-height:1.55;
    margin-top:5px;
}

.playbook-step-badge {
    display:inline-block;
    margin-top:8px;
    margin-right:5px;
    padding:3px 7px;
    border:1px solid #334155;
    border-radius:3px;
    color:#9aa8ba;
    font-size:9px;
}

.playbook-history {
    background:#0b111a;
    border-left:2px solid #334155;
    padding:9px 11px;
    margin:6px 0;
    color:#8e9bad;
    font-size:10px;
    line-height:1.55;
}



/* ======================================================
   Live CRITICAL Alert
   ====================================================== */

.live-alert-wrap {
    background:
        linear-gradient(
            90deg,
            rgba(127, 29, 29, 0.38),
            rgba(69, 10, 10, 0.20)
        );
    border: 1px solid #7f1d1d;
    border-left: 4px solid #ff5c68;
    border-radius: 5px;
    padding: 14px 16px;
    margin: 0 0 18px 0;
}

.live-alert-top {
    display: flex;
    justify-content: space-between;
    gap: 16px;
    align-items: center;
}

.live-alert-title {
    color: #ff818a;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0.04em;
}

.live-alert-time {
    color: #8e9bad;
    font-size: 9px;
    font-family: Consolas, monospace;
}

.live-alert-main {
    color: #f7d7da;
    font-size: 14px;
    font-weight: 700;
    margin-top: 7px;
}

.live-alert-meta {
    color: #b9a3a7;
    font-size: 10px;
    margin-top: 6px;
}

.live-monitor-ok {
    background: #0c1916;
    border: 1px solid #1e3b32;
    border-left: 4px solid #35d07f;
    border-radius: 5px;
    padding: 10px 14px;
    color: #75d9a4;
    font-size: 10px;
    margin: 0 0 18px 0;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# 공통 함수
# =========================================================

def load_events():
    try:
        response = requests.get(
            f"{API_URL}/events",
            timeout=5
        )

        if response.status_code == 200:
            return response.json()

        return []

    except requests.exceptions.RequestException:
        return []


def load_risk_explanation(event_id):
    try:
        response = requests.get(
            f"{API_URL}/events/{event_id}/risk-explanation",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text

        return False, {"detail": detail}

    except requests.exceptions.RequestException as error:
        return False, {"detail": str(error)}


def load_monitored_users():
    try:
        response = requests.get(
            f"{API_URL}/users",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        return False, []

    except requests.exceptions.RequestException:
        return False, []


def load_behavior_changes(
    user=None,
    status=None
):
    params = {}

    if user:
        params["user"] = user

    if status:
        params["status"] = status

    try:
        response = requests.get(
            f"{API_URL}/behavior-changes",
            params=params,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()

            if isinstance(data, list):
                return True, data

            if isinstance(data, dict):
                return True, data.get(
                    "value",
                    data.get(
                        "items",
                        data.get(
                            "behavior_changes",
                            []
                        )
                    )
                )

            return True, []

        return False, []

    except requests.exceptions.RequestException:
        return False, []


def decide_behavior_change(
    observation_id,
    action,
    note=None
):
    try:
        response = requests.post(
            f"{API_URL}/behavior-changes/"
            f"{observation_id}/decision",
            json={
                "action": action,
                "note": (
                    note.strip()
                    if note
                    else None
                )
            },
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except ValueError:
            detail = response.text

        return False, {
            "detail": detail
        }

    except requests.exceptions.RequestException as error:
        return False, {
            "detail": str(error)
        }


def load_user_behavior_profile(username):
    try:
        response = requests.get(
            f"{API_URL}/users/{username}/behavior-profile",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        return False, {}

    except requests.exceptions.RequestException:
        return False, {}




def load_dynamic_user_risk(username):
    try:
        response = requests.get(
            f"{API_URL}/users/{username}/dynamic-risk",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except ValueError:
            detail = response.text

        return False, {
            "detail": detail
        }

    except requests.exceptions.RequestException as error:
        return False, {
            "detail": str(error)
        }


def create_monitored_user(
    username,
    display_name=None,
    department=None,
    role=None
):
    payload = {
        "username": username.strip(),
        "display_name": (
            display_name.strip()
            if display_name
            else None
        ),
        "department": (
            department.strip()
            if department
            else None
        ),
        "role": (
            role.strip()
            if role
            else None
        )
    }

    try:
        response = requests.post(
            f"{API_URL}/users",
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except ValueError:
            detail = response.text

        return False, {
            "detail": detail
        }

    except requests.exceptions.RequestException as error:
        return False, {
            "detail": str(error)
        }


def set_monitored_user_enabled(
    username,
    enabled
):
    action = (
        "enable"
        if enabled
        else "disable"
    )

    try:
        response = requests.post(
            f"{API_URL}/users/{username}/{action}",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except ValueError:
            detail = response.text

        return False, {
            "detail": detail
        }

    except requests.exceptions.RequestException as error:
        return False, {
            "detail": str(error)
        }


def delete_monitored_user(username):
    try:
        response = requests.delete(
            f"{API_URL}/users/{username}",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except ValueError:
            detail = response.text

        return False, {
            "detail": detail
        }

    except requests.exceptions.RequestException as error:
        return False, {
            "detail": str(error)
        }


def run_demo_api(endpoint, method="POST"):
    try:
        if method == "DELETE":
            response = requests.delete(
                f"{API_URL}{endpoint}",
                timeout=30
            )
        else:
            response = requests.post(
                f"{API_URL}{endpoint}",
                timeout=30
            )

        if response.status_code == 200:
            return True, response.json()

        return False, {
            "detail": response.text
        }

    except requests.exceptions.RequestException as error:
        return False, {
            "detail": str(error)
        }



def load_incidents():
    try:
        response = requests.get(
            f"{API_URL}/incidents",
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                return True, data
            if isinstance(data, dict):
                return True, data.get("incidents", [])
            return True, []

        return False, []

    except requests.exceptions.RequestException:
        return False, []


def load_incident_detail(incident_id):
    try:
        response = requests.get(
            f"{API_URL}/incidents/{incident_id}",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        return False, {}

    except requests.exceptions.RequestException:
        return False, {}



def run_ai_analysis(event_id):
    try:
        response = requests.post(
            f"{API_URL}/ai-analysis/{event_id}",
            timeout=90
        )

        if response.status_code == 200:
            return True, response.json()

        return False, {
            "detail": response.text
        }

    except requests.exceptions.RequestException as error:
        return False, {
            "detail": str(error)
        }


def display_value(value):
    if value is None:
        return "-"

    try:
        if pd.isna(value):
            return "-"
    except (TypeError, ValueError):
        pass

    return value


def safe_html(value):
    value = str(
        display_value(value)
    )

    return (
        value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def section_header(title):
    html = (
        '<div class="section-header">'
        f'<div class="section-title">{safe_html(title)}</div>'
        '<div class="section-line"></div>'
        '</div>'
    )

    st.markdown(
        html,
        unsafe_allow_html=True
    )


def risk_class(level):
    level = str(level).upper()

    if level == "CRITICAL":
        return "risk-critical"

    if level == "HIGH":
        return "risk-high"

    if level == "MEDIUM":
        return "risk-medium"

    return "risk-low"



def dynamic_badge_class(level):
    level = str(level).upper()

    if level == "CRITICAL":
        return "dynamic-badge-critical"

    if level == "HIGH":
        return "dynamic-badge-high"

    if level == "MEDIUM":
        return "dynamic-badge-medium"

    return "dynamic-badge-low"


def incident_class(level):
    level = str(level).upper()

    if level == "CRITICAL":
        return "incident-critical"

    if level == "HIGH":
        return "incident-high"

    if level == "MEDIUM":
        return "incident-medium"

    return "incident-low"


def format_timestamp(value):
    try:
        timestamp = pd.to_datetime(value)

        return timestamp.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:
        return str(
            display_value(value)
        )



def _live_incident_id(item):
    return item.get(
        "incident_id",
        item.get("id")
    )


def _live_incident_sort_key(item):
    incident_id = _live_incident_id(item)

    try:
        incident_id = int(incident_id or 0)
    except (TypeError, ValueError):
        incident_id = 0

    return (
        str(item.get("last_seen", "")),
        incident_id
    )


def _critical_activity_signature(item):
    """
    같은 Incident라도 last_seen / correlation_score가 바뀌면
    새로운 CRITICAL 활동으로 인식한다.
    """
    return (
        str(_live_incident_id(item)),
        str(item.get("last_seen", "")),
        str(item.get("correlation_score", "")),
    )



st.markdown(
    """
    <style>
    .st-key-critical_alert_box {
        border: 1px solid #ff2f45 !important;
        border-radius: 4px !important;
        background:
            linear-gradient(
                180deg,
                rgba(83, 9, 19, 0.52) 0%,
                rgba(45, 8, 14, 0.45) 100%
            ) !important;
        padding: 12px 14px 10px 14px !important;
        margin-bottom: 10px !important;
    }

    .st-key-critical_alert_box [data-testid="stButton"] button {
        min-height: 38px !important;
        margin-top: 4px !important;
        font-weight: 700 !important;
        border-radius: 5px !important;
        transition: all 0.15s ease !important;
    }

    /* 첫 번째 버튼: 사고 상세 보기 */
    .st-key-critical_alert_box [data-testid="stHorizontalBlock"]
    > div:nth-child(1) [data-testid="stButton"] button {
        background: #d9273f !important;
        border: 1px solid #ff5a6f !important;
        color: #ffffff !important;
        box-shadow: 0 0 0 1px rgba(255, 90, 111, 0.08) inset !important;
    }

    .st-key-critical_alert_box [data-testid="stHorizontalBlock"]
    > div:nth-child(1) [data-testid="stButton"] button:hover {
        background: #ef334d !important;
        border-color: #ff7182 !important;
    }

    /* 두 번째 버튼: 확인 */
    .st-key-critical_alert_box [data-testid="stHorizontalBlock"]
    > div:nth-child(2) [data-testid="stButton"] button {
        background: rgba(255, 255, 255, 0.06) !important;
        border: 1px solid #c7d2e1 !important;
        color: #f5f7fa !important;
    }

    .st-key-critical_alert_box [data-testid="stHorizontalBlock"]
    > div:nth-child(2) [data-testid="stButton"] button:hover {
        background: rgba(255, 255, 255, 0.12) !important;
        border-color: #ffffff !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

def _render_live_critical_alert():
    incidents_ok, incidents = load_incidents()

    if not incidents_ok:
        st.markdown(
            '<div class="live-monitor-ok" '
            'style="border-left-color:#f5a742;color:#f5a742;">'
            '● LIVE ALERT · Incident API 연결 확인 필요'
            '</div>',
            unsafe_allow_html=True
        )
        return

    critical_incidents = [
        item
        for item in incidents
        if str(
            item.get("severity", "")
        ).upper() == "CRITICAL"
        and str(
            item.get("status", "OPEN")
        ).upper() != "CLOSED"
    ]

    critical_incidents.sort(
        key=_live_incident_sort_key,
        reverse=True
    )

    current_signatures = {
        _critical_activity_signature(item)
        for item in critical_incidents
    }

    # Toast 중복 방지용 signature 집합
    if "live_alert_initialized" not in st.session_state:
        st.session_state["live_alert_initialized"] = True
        st.session_state["notified_critical_signatures"] = set(
            current_signatures
        )
        st.session_state["new_critical_activity_signature"] = None

    # SOC 담당자가 '확인'한 활동 signature.
    # 같은 Incident라도 last_seen / correlation_score가 바뀌면
    # 새로운 signature가 되므로 다시 알람이 표시된다.
    if "acknowledged_critical_signatures" not in st.session_state:
        st.session_state["acknowledged_critical_signatures"] = set()

    notified_signatures = set(
        st.session_state.get(
            "notified_critical_signatures",
            set()
        )
    )

    for item in critical_incidents:
        signature = _critical_activity_signature(item)

        if signature not in notified_signatures:
            incident_title = (
                item.get("title")
                or item.get("incident_type")
                or "고위험 보안 사고"
            )
            incident_user = item.get("user", "-")
            incident_id = _live_incident_id(item)

            st.toast(
                f"NEW CRITICAL ACTIVITY · "
                f"Incident #{incident_id} · "
                f"{incident_title} · {incident_user}"
            )

            notified_signatures.add(signature)
            st.session_state[
                "new_critical_activity_signature"
            ] = signature

            # 가장 최근 신규 활동 하나만 강조
            break

    st.session_state["notified_critical_signatures"] = (
        notified_signatures
    )

    if not critical_incidents:
        st.markdown(
            '<div class="live-monitor-ok">'
            '● LIVE ALERT MONITORING · '
            '현재 OPEN CRITICAL Incident 없음'
            '</div>',
            unsafe_allow_html=True
        )
        return

    latest = critical_incidents[0]

    incident_id = _live_incident_id(latest)
    incident_title = (
        latest.get("title")
        or latest.get("incident_type")
        or "고위험 보안 사고"
    )
    incident_user = latest.get("user", "-")
    correlation_score = latest.get(
        "correlation_score",
        "-"
    )
    last_seen = latest.get(
        "last_seen",
        "-"
    )

    latest_signature = _critical_activity_signature(
        latest
    )

    acknowledged_signatures = set(
        st.session_state.get(
            "acknowledged_critical_signatures",
            set()
        )
    )

    is_acknowledged = (
        latest_signature in acknowledged_signatures
    )

    is_new_activity = (
        st.session_state.get(
            "new_critical_activity_signature"
        )
        == latest_signature
    )

    # 이미 확인한 동일 활동은 큰 빨간 알람을 계속 점유하지 않는다.
    # Incident 자체는 OPEN 상태로 그대로 유지한다.
    if is_acknowledged:
        compact_col1, compact_col2 = st.columns(
            [6, 1.5]
        )

        with compact_col1:
            st.markdown(
                (
                    '<div class="live-monitor-ok" '
                    'style="border-left-color:#ff6b6b;color:#ffb0b0;">'
                    f'● OPEN CRITICAL INCIDENT {len(critical_incidents)}건'
                    f' · Incident #{safe_html(incident_id)}'
                    f' · 확인 완료'
                    '</div>'
                ),
                unsafe_allow_html=True
            )

        with compact_col2:
            if st.button(
                "사고 상세",
                key=f"open_ack_incident_{incident_id}_{latest_signature}",
                use_container_width=True
            ):
                st.session_state["page"] = "보안 사고 분석"
                st.session_state[
                    "target_incident_id"
                ] = str(incident_id)
                st.session_state[
                    "correlated_incident_level_filter"
                ] = "전체"
                st.session_state[
                    "correlated_incident_status_filter"
                ] = "전체"
                st.rerun()

        return

    if is_new_activity:
        alert_label = "● NEW CRITICAL ACTIVITY"
        alert_sub = "방금 새로운 CRITICAL 공격 활동이 탐지되었습니다."
    else:
        alert_label = "● LIVE CRITICAL INCIDENT"
        alert_sub = "확인되지 않은 OPEN CRITICAL Incident가 있습니다."

    # 알람 내용과 버튼을 하나의 빨간 경보 컨테이너 안에 배치
    with st.container(
        border=True,
        key="critical_alert_box"
    ):
        st.markdown(
            f"""
            <div class="live-alert-top">
                <div class="live-alert-title">
                    {safe_html(alert_label)}
                </div>
                <div class="live-alert-time">
                    {safe_html(format_timestamp(last_seen))}
                </div>
            </div>
            <div class="live-alert-main">
                {safe_html(incident_title)}
            </div>
            <div class="live-alert-meta">
                {safe_html(alert_sub)}
                <br>
                Incident #{safe_html(incident_id)}
                &nbsp;·&nbsp;
                사용자 {safe_html(incident_user)}
                &nbsp;·&nbsp;
                Correlation {safe_html(correlation_score)}
                &nbsp;·&nbsp;
                OPEN CRITICAL {len(critical_incidents)}건
            </div>
            """,
            unsafe_allow_html=True
        )

        detail_col, ack_col = st.columns(
            [4.5, 1.5]
        )

        with detail_col:
            if st.button(
                f"사고 상세 보기 · Incident #{incident_id}",
                key=f"open_live_incident_{incident_id}_{latest_signature}",
                type="primary",
                use_container_width=True
            ):
                st.session_state["page"] = "보안 사고 분석"
                st.session_state[
                    "target_incident_id"
                ] = str(incident_id)
                st.session_state[
                    "correlated_incident_level_filter"
                ] = "전체"
                st.session_state[
                    "correlated_incident_status_filter"
                ] = "전체"
                st.rerun()

        # 확인은 Incident 종료가 아니라 현재 알람 활동만 확인 처리
        with ack_col:
            if st.button(
                "확인",
                key=f"ack_live_incident_{incident_id}_{latest_signature}",
                use_container_width=True
            ):
                acknowledged_signatures.add(
                    latest_signature
                )
                st.session_state[
                    "acknowledged_critical_signatures"
                ] = acknowledged_signatures

                if (
                    st.session_state.get(
                        "new_critical_activity_signature"
                    )
                    == latest_signature
                ):
                    st.session_state[
                        "new_critical_activity_signature"
                    ] = None

                st.rerun()

def render_live_alert_monitor():
    # 최신 Streamlit에서는 이 영역만 3초마다 갱신한다.
    if hasattr(st, "fragment"):
        @st.fragment(run_every="3s")
        def _live_alert_fragment():
            _render_live_critical_alert()

        _live_alert_fragment()
        return

    # 구버전에서도 앱 자체는 정상 동작한다.
    _render_live_critical_alert()




def detail_card(label, value):
    html = (
        '<div class="detail-box">'
        f'<div class="detail-label">{safe_html(label)}</div>'
        f'<div class="detail-value">{safe_html(value)}</div>'
        '</div>'
    )

    st.markdown(
        html,
        unsafe_allow_html=True
    )


def event_type_korean(event_type):
    mapping = {
        "login_success": "로그인 성공",
        "login_failure": "로그인 실패",
        "login_failed": "로그인 실패",
        "file_access": "파일 접근",
        "usb_connected": "USB 연결",
        "process_execution": "프로세스 실행",
        "document_analysis": "문서 분석"
    }

    return mapping.get(
        str(event_type),
        str(event_type)
    )


def load_event_metrics():
    """
    실제 /events 조회 지연과 최근 60초 이벤트 수를 측정한다.
    임의 성능값을 만들지 않고 현재 관찰된 데이터만 사용한다.
    """
    started = perf_counter()

    try:
        response = requests.get(
            f"{API_URL}/events",
            params={"limit": 500},
            timeout=10
        )
        api_latency_ms = (
            perf_counter() - started
        ) * 1000

        if response.status_code != 200:
            return {
                "api_latency_ms": api_latency_ms,
                "recent_60s_events": 0,
                "observed_eps": 0.0,
                "loaded_events": 0,
            }

        data = response.json()

        if not isinstance(data, list):
            data = []

        recent_60s_events = 0

        if data:
            now = pd.Timestamp.now()

            for item in data:
                raw_timestamp = item.get("timestamp")

                if not raw_timestamp:
                    continue

                try:
                    event_time = pd.to_datetime(
                        raw_timestamp,
                        errors="coerce"
                    )

                    if pd.isna(event_time):
                        continue

                    delta = (
                        now - event_time
                    ).total_seconds()

                    if 0 <= delta <= 60:
                        recent_60s_events += 1

                except Exception:
                    continue

        return {
            "api_latency_ms": round(
                api_latency_ms,
                2
            ),
            "recent_60s_events": recent_60s_events,
            "observed_eps": round(
                recent_60s_events / 60.0,
                2
            ),
            "loaded_events": len(data),
        }

    except requests.exceptions.RequestException:
        return {
            "api_latency_ms": None,
            "recent_60s_events": 0,
            "observed_eps": 0.0,
            "loaded_events": 0,
        }


def load_event_dataframe():
    events = load_events()

    if events:
        current_df = pd.DataFrame(events)
    else:
        current_df = pd.DataFrame()

    if not current_df.empty:
        # 발표/운영 화면에서는 현재 활성 모니터링 사용자만 표시한다.
        # CERT 100K 평가 데이터는 security_events에 그대로 보존되지만
        # 일반 보안 현황/이벤트/사용자 분석 통계에는 섞이지 않는다.
        users_ok, monitored_users = load_monitored_users()
        if users_ok and monitored_users and "user" in current_df.columns:
            active_users = {
                str(item.get("username"))
                for item in monitored_users
                if item.get("monitoring_enabled")
            }
            if active_users:
                current_df = current_df[
                    current_df["user"].astype(str).isin(active_users)
                ].copy()

        if "timestamp" in current_df.columns:
            current_df["timestamp"] = pd.to_datetime(
                current_df["timestamp"],
                errors="coerce"
            )
            current_df = current_df.sort_values(
                "timestamp",
                ascending=False
            )

        if "risk_score" in current_df.columns:
            current_df["risk_score"] = pd.to_numeric(
                current_df["risk_score"],
                errors="coerce"
            ).fillna(0)

        if "anomaly_score" in current_df.columns:
            current_df["anomaly_score"] = pd.to_numeric(
                current_df["anomaly_score"],
                errors="coerce"
            ).fillna(0)

    return current_df


def make_user_stats(df):
    if (
        "user" not in df.columns
        or "risk_score" not in df.columns
    ):
        return pd.DataFrame(
            columns=[
                "user",
                "average_risk",
                "max_risk",
                "event_count"
            ]
        )

    result = (
        df.groupby("user")
        .agg(
            average_risk=("risk_score", "mean"),
            max_risk=("risk_score", "max"),
            event_count=("id", "count")
        )
        .reset_index()
    )

    result["average_risk"] = (
        result["average_risk"].round(2)
    )

    result["max_risk"] = (
        result["max_risk"].round(2)
    )

    return result.sort_values(
        "average_risk",
        ascending=False
    )


def render_user_risk_panel(user_stats):
    if user_stats.empty:
        st.info(
            "사용자 위험도 데이터가 없습니다."
        )
        return

    rows = []

    for _, row in user_stats.head(8).iterrows():
        user = safe_html(
            row["user"]
        )

        score = float(
            row["average_risk"]
        )

        width = max(
            1,
            min(score, 100)
        )

        rows.append(
            '<div class="risk-row">'
            f'<div class="risk-user">{user}</div>'
            f'<div class="risk-number">{score:.1f}</div>'
            '<div class="bar-track">'
            f'<div class="bar-fill" style="width:{width:.1f}%"></div>'
            '</div>'
            '</div>'
        )

    html = (
        '<div class="soc-panel">'
        '<div class="panel-title">사용자 위험도</div>'
        '<div class="panel-sub">'
        '사용자별 평균 Risk Score · 최대 8명 표시'
        '</div>'
        + "".join(rows)
        + '</div>'
    )

    st.markdown(
        html,
        unsafe_allow_html=True
    )


def render_severity_panel(risk_counts):
    total = int(
        risk_counts.sum()
    )

    settings = [
        (
            "CRITICAL",
            "fill-critical",
            "text-critical"
        ),
        (
            "HIGH",
            "fill-high",
            "text-high"
        ),
        (
            "MEDIUM",
            "fill-medium",
            "text-medium"
        ),
        (
            "LOW",
            "fill-low",
            "text-low"
        )
    ]

    rows = []

    for level, fill_class, text_class in settings:
        count = int(
            risk_counts.get(
                level,
                0
            )
        )

        percent = (
            count / total * 100
            if total > 0
            else 0
        )

        width = 0

        if count > 0:
            width = max(
                2.5,
                percent
            )

        rows.append(
            '<div class="severity-row">'
            f'<div class="severity-name {text_class}">{level}</div>'
            f'<div class="severity-count">{count:,}</div>'
            '<div class="bar-track">'
            f'<div class="bar-fill {fill_class}" '
            f'style="width:{width:.2f}%"></div>'
            '</div>'
            f'<div class="severity-percent">{percent:.1f}%</div>'
            '</div>'
        )

    html = (
        '<div class="soc-panel">'
        '<div class="panel-title">위험 등급 현황</div>'
        '<div class="panel-sub">'
        '전체 이벤트의 Risk Level 분포'
        '</div>'
        + "".join(rows)
        + '</div>'
    )

    st.markdown(
        html,
        unsafe_allow_html=True
    )


def render_kpis(df):
    total_events = len(df)

    if "anomaly_score" in df.columns:
        anomaly_count = len(
            df[
                df["anomaly_score"] >= 50
            ]
        )
    else:
        anomaly_count = 0

    if "risk_level" in df.columns:
        high_risk_count = len(
            df[
                df["risk_level"].isin(
                    [
                        "HIGH",
                        "CRITICAL"
                    ]
                )
            ]
        )

        critical_count = len(
            df[
                df["risk_level"]
                == "CRITICAL"
            ]
        )
    else:
        high_risk_count = 0
        critical_count = 0

    unique_users = (
        df["user"].nunique()
        if "user" in df.columns
        else 0
    )

    k1, k2, k3, k4, k5 = st.columns(5)

    cards = [
        (
            k1,
            "전체 이벤트",
            f"{total_events:,}",
            "수집된 전체 보안 이벤트",
            ""
        ),
        (
            k2,
            "이상행동 탐지",
            f"{anomaly_count:,}",
            "Isolation Forest Score ≥ 50",
            ""
        ),
        (
            k3,
            "고위험 이벤트",
            f"{high_risk_count:,}",
            "HIGH + CRITICAL",
            "kpi-warning"
        ),
        (
            k4,
            "긴급 이벤트",
            f"{critical_count:,}",
            "즉시 확인이 필요한 이벤트",
            "kpi-danger"
        ),
        (
            k5,
            "모니터링 사용자",
            f"{unique_users:,}",
            "관찰된 사용자 계정",
            ""
        )
    ]

    for (
        column,
        label,
        value,
        foot,
        css_class
    ) in cards:

        with column:
            html = (
                '<div class="kpi-card">'
                f'<div class="kpi-label">{label}</div>'
                f'<div class="kpi-value {css_class}">{value}</div>'
                f'<div class="kpi-foot">{foot}</div>'
                '</div>'
            )

            st.markdown(
                html,
                unsafe_allow_html=True
            )


def render_alert_table(df, height=300):
    if "risk_level" not in df.columns:
        st.info(
            "위험 등급 데이터가 없습니다."
        )
        return

    danger_df = df[
        df["risk_level"].isin(
            [
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]
        )
    ].copy()

    if danger_df.empty:
        st.success(
            "현재 탐지된 위험 이벤트가 없습니다."
        )
        return

    columns = [
        "id",
        "timestamp",
        "risk_level",
        "risk_score",
        "user",
        "event_type",
        "source_ip",
        "file_name",
        "process_name"
    ]

    available = [
        column
        for column in columns
        if column in danger_df.columns
    ]

    display_df = (
        danger_df[
            available
        ]
        .head(50)
        .copy()
    )

    if "timestamp" in display_df.columns:
        display_df["timestamp"] = (
            display_df["timestamp"]
            .dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    if "event_type" in display_df.columns:
        display_df["event_type"] = (
            display_df["event_type"]
            .apply(event_type_korean)
        )

    display_df = display_df.rename(
        columns={
            "id": "이벤트 ID",
            "timestamp": "탐지 시간",
            "risk_level": "위험 등급",
            "risk_score": "Risk Score",
            "user": "사용자",
            "event_type": "이벤트 유형",
            "source_ip": "Source IP",
            "file_name": "파일",
            "process_name": "프로세스"
        }
    )

    st.dataframe(
        display_df.fillna("-"),
        use_container_width=True,
        hide_index=True,
        height=height
    )


def render_timeline(
    source_df,
    height=440
):
    columns = [
        "id",
        "timestamp",
        "user",
        "event_type",
        "source_ip",
        "login_fail_count",
        "file_name",
        "file_grade",
        "file_access_count",
        "usb_connected",
        "process_name",
        "anomaly_score",
        "risk_score",
        "risk_level"
    ]

    available = [
        column
        for column in columns
        if column in source_df.columns
    ]

    timeline = (
        source_df[
            available
        ]
        .copy()
    )

    if "timestamp" in timeline.columns:
        timeline["timestamp"] = (
            timeline["timestamp"]
            .dt.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

    if "event_type" in timeline.columns:
        timeline["event_type"] = (
            timeline["event_type"]
            .apply(event_type_korean)
        )

    timeline = timeline.rename(
        columns={
            "id": "이벤트 ID",
            "timestamp": "발생 시간",
            "user": "사용자",
            "event_type": "이벤트 유형",
            "source_ip": "Source IP",
            "login_fail_count": "로그인 실패",
            "file_name": "파일",
            "file_grade": "파일 등급",
            "file_access_count": "파일 접근",
            "usb_connected": "USB",
            "process_name": "프로세스",
            "anomaly_score": "Anomaly Score",
            "risk_score": "Risk Score",
            "risk_level": "위험 등급"
        }
    )

    st.dataframe(
        timeline.fillna("-"),
        use_container_width=True,
        hide_index=True,
        height=height
    )


# =========================================================
# 페이지 상태
# =========================================================

if "page" not in st.session_state:
    st.session_state["page"] = "보안 현황"

if "ai_results" not in st.session_state:
    st.session_state["ai_results"] = {}

if "adaptive_demo_result" not in st.session_state:
    st.session_state["adaptive_demo_result"] = None


# =========================================================
# 사이드바
# =========================================================

brand_html = """
<div class="sidebar-brand">
<div class="sidebar-brand-name">SENTINEL</div>
<div class="sidebar-brand-sub">SIEM / UEBA 보안 관제 플랫폼</div>
</div>
"""

st.sidebar.markdown(
    brand_html,
    unsafe_allow_html=True
)

st.sidebar.markdown(
    '<div class="side-section">보안 관제</div>',
    unsafe_allow_html=True
)


if st.sidebar.button(
    "보안 현황",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "보안 현황"
        else "secondary"
    )
):
    st.session_state["page"] = "보안 현황"
    st.rerun()


if st.sidebar.button(
    "이벤트 모니터링",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "이벤트 모니터링"
        else "secondary"
    )
):
    st.session_state["page"] = "이벤트 모니터링"
    st.rerun()


if st.sidebar.button(
    "보안 사고 분석",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "보안 사고 분석"
        else "secondary"
    )
):
    st.session_state["page"] = "보안 사고 분석"
    st.rerun()


if st.sidebar.button(
    "사용자 행동 분석",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "사용자 행동 분석"
        else "secondary"
    )
):
    st.session_state["page"] = "사용자 행동 분석"
    st.rerun()


if st.sidebar.button(
    "행동 승인 관리",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "행동 승인 관리"
        else "secondary"
    )
):
    st.session_state["page"] = "행동 승인 관리"
    st.rerun()


if st.sidebar.button(
    "CERT 100K 검증",
    use_container_width=True,
    type=(
        "primary"
        if st.session_state["page"] == "CERT 100K 검증"
        else "secondary"
    )
):
    st.session_state["page"] = "CERT 100K 검증"
    st.rerun()


engine_html = """
<div class="side-section">탐지 엔진</div>
<div class="engine-row">
<span>Rule Engine</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>Isolation Forest</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>User Baseline</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>Sequence Detection</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>Peer Group UEBA</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>Dynamic User Risk</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>Incident Correlation</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>PII Detection</span>
<span class="engine-online">정상</span>
</div>
<div class="engine-row">
<span>LLM Analyst</span>
<span class="engine-online">준비</span>
</div>
"""

st.sidebar.markdown(
    engine_html,
    unsafe_allow_html=True
)


st.sidebar.markdown(
    '<div class="side-section">시연 제어</div>',
    unsafe_allow_html=True
)


if st.sidebar.button(
    "정상 시나리오 실행",
    use_container_width=True
):
    with st.spinner(
        "정상 사용자 이벤트 생성 중..."
    ):
        success, result = run_demo_api(
            "/demo/normal"
        )

    if success:
        st.sidebar.success(
            "정상 시나리오 완료"
        )
        st.rerun()

    else:
        st.sidebar.error(
            result.get(
                "detail",
                "실행 실패"
            )
        )


if st.sidebar.button(
    "공격 시나리오 실행",
    use_container_width=True
):
    with st.spinner(
        "공격 시퀀스 분석 중..."
    ):
        success, result = run_demo_api(
            "/demo/attack"
        )

    if success:
        final_level = result.get(
            "final_risk_level",
            "-"
        )

        final_score = result.get(
            "final_risk_score",
            "-"
        )

        st.sidebar.success(
            f"{final_level} · Risk {final_score}"
        )

        st.rerun()

    else:
        st.sidebar.error(
            result.get(
                "detail",
                "실행 실패"
            )
        )


reset_confirm = st.sidebar.checkbox(
    "전체 이벤트 삭제 허용"
)

if st.sidebar.button(
    "이벤트 데이터 초기화",
    use_container_width=True,
    disabled=not reset_confirm
):
    with st.spinner(
        "이벤트 데이터 초기화 중..."
    ):
        success, result = run_demo_api(
            "/demo/reset",
            method="DELETE"
        )

    if success:
        st.session_state[
            "ai_results"
        ] = {}

        st.sidebar.success(
            "이벤트 데이터 초기화 완료"
        )

        st.rerun()

    else:
        st.sidebar.error(
            result.get(
                "detail",
                "초기화 실패"
            )
        )


st.sidebar.markdown(
    '<div class="side-section">시스템</div>',
    unsafe_allow_html=True
)

auto_refresh_enabled = st.sidebar.toggle(
    "실시간 자동 갱신",
    value=st.session_state.get(
        "dashboard_auto_refresh",
        True
    ),
    help="보안 현황의 이벤트 기반 영역을 하나의 동기화된 3초 갱신으로 업데이트합니다."
)

st.session_state[
    "dashboard_auto_refresh"
] = auto_refresh_enabled

if auto_refresh_enabled:
    st.sidebar.caption(
        "동기화 실시간 갱신 · 3초"
    )
else:
    st.sidebar.caption(
        "자동 갱신 중지"
    )

if st.sidebar.button(
    "이벤트 데이터 새로고침",
    use_container_width=True
):
    st.rerun()

st.sidebar.caption(
    "VM1 중앙 분석 서버"
)

st.sidebar.caption(
    "API · 127.0.0.1:8000"
)



st.markdown(
    """
    <style>
    /* 실시간 갱신 시 시각적 튐 최소화 */
    div[data-testid="stMetric"],
    div[data-testid="stDataFrame"],
    div[data-testid="stTable"],
    div[data-testid="stPlotlyChart"],
    div[data-testid="stMarkdownContainer"] {
        transition: none !important;
        animation: none !important;
    }

    .js-plotly-plot,
    .plotly,
    .plot-container,
    .svg-container {
        transition: none !important;
        animation: none !important;
    }

    /* fragment 교체 중 레이아웃 높이가 급격히 접히는 느낌 완화 */
    div[data-testid="stVerticalBlock"] {
        scroll-margin-top: 0 !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# =========================================================
# 데이터 로딩
# =========================================================

df = load_event_dataframe()


# =========================================================
# 페이지 헤더
# =========================================================

page = st.session_state["page"]

page_info = {
    "보안 현황": (
        "내부자 위협 보안 관제 센터",
        "사용자 행동 분석 · 이상행동 탐지 · 보안 사고 대응"
    ),
    "이벤트 모니터링": (
        "보안 이벤트 모니터링",
        "Windows 보안 이벤트 · 파일 접근 · USB · 프로세스 실행 모니터링"
    ),
    "보안 사고 분석": (
        "보안 사고 분석",
        "Incident Correlation · Attack Storyline · 연관 이벤트 · AI 보조 분석"
    ),
    "사용자 행동 분석": (
        "사용자 행동 분석",
        "사용자별 행동 패턴 · 위험도 · 활동 이력 분석"
    ),
    "행동 승인 관리": (
        "행동 변화 승인 관리",
        "Human-in-the-loop · 예외 승인 · 위험 유지 · 재관찰"
    ),
    "CERT 100K 검증": (
        "CERT 100K 성능 검증",
        "CERT Insider Threat Dataset r4.2 · 100,000건 기반 탐지 성능 평가"
    )
}

title, subtitle = page_info[
    page
]

current_time = datetime.now().strftime(
    "%Y-%m-%d  %H:%M:%S"
)

header_html = f"""
<div class="soc-header">
<div>
<div class="soc-title">{safe_html(title)}</div>
<div class="soc-subtitle">{safe_html(subtitle)}</div>
</div>
<div style="text-align:right;">
<div class="system-online">● 시스템 정상</div>
<div style="color:#526176;font-size:9px;margin-top:7px;font-family:monospace;">
{current_time}
</div>
</div>
</div>
"""

st.markdown(
    header_html,
    unsafe_allow_html=True
)


# =========================================================
# Live CRITICAL Incident Alert
# =========================================================

# 보안 현황에서는 아래의 단일 동기화 fragment 안에서 같이 갱신한다.
# 다른 페이지에서는 기존처럼 독립적으로 표시한다.
if page != "보안 현황":
    render_live_alert_monitor()


# =========================================================
# 실시간 이벤트 데이터 상태
# =========================================================

def _render_live_event_strip():
    live_df = load_event_dataframe()

    if live_df.empty:
        st.caption("LIVE EVENT · 수집 이벤트 없음")
        return

    latest_id = (
        int(live_df["id"].max())
        if "id" in live_df.columns
        else "-"
    )

    latest_time = "-"
    if "timestamp" in live_df.columns:
        valid_times = live_df["timestamp"].dropna()
        if not valid_times.empty:
            latest_time = valid_times.max().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    critical_count = 0
    if "risk_level" in live_df.columns:
        critical_count = int(
            (live_df["risk_level"] == "CRITICAL").sum()
        )

    st.caption(
        f"LIVE EVENT · 최신 ID {latest_id} · "
        f"최근 수집 {latest_time} · "
        f"현재 조회 구간 CRITICAL {critical_count}건"
    )

    # 최근 실시간 수집 이벤트 3건
    display_df = live_df.copy()

    if "id" in display_df.columns:
        display_df = display_df.sort_values(
            "id",
            ascending=False
        )

    live_rows = display_df.head(3)

    if not live_rows.empty:
        st.markdown(
            """
            <div style="
                margin-top:6px;
                margin-bottom:4px;
                color:#7f92aa;
                font-size:10px;
                letter-spacing:0.06em;
                font-weight:700;
            ">
                LIVE INGEST FEED
            </div>
            """,
            unsafe_allow_html=True
        )

        for _, row in live_rows.iterrows():
            event_id = row.get("id", "-")

            event_time = row.get("timestamp", "-")
            if hasattr(event_time, "strftime"):
                event_time = event_time.strftime("%H:%M:%S")

            user = row.get("user", "-")
            event_type = event_type_korean(
                row.get("event_type", "-")
            )

            risk_score = row.get("risk_score", 0)
            try:
                risk_score = f"{float(risk_score):.2f}"
            except Exception:
                risk_score = str(risk_score)

            risk_level = str(
                row.get("risk_level", "-")
            )

            st.markdown(
                f"""
                <div style="
                    display:flex;
                    align-items:center;
                    gap:14px;
                    padding:5px 8px;
                    margin-bottom:3px;
                    border:1px solid #1c2a3b;
                    border-radius:4px;
                    background:rgba(13,24,38,0.72);
                    font-size:11px;
                    font-family:monospace;
                ">
                    <span style="color:#63758c;min-width:62px;">
                        #{safe_html(event_id)}
                    </span>
                    <span style="color:#8ea0b8;min-width:68px;">
                        {safe_html(event_time)}
                    </span>
                    <span style="color:#d6e4f4;min-width:90px;">
                        {safe_html(user)}
                    </span>
                    <span style="color:#9ecbff;min-width:105px;">
                        {safe_html(event_type)}
                    </span>
                    <span style="color:#d7dde7;">
                        Risk {safe_html(risk_score)}
                    </span>
                    <span style="color:#f1b84b;font-weight:700;">
                        {safe_html(risk_level)}
                    </span>
                </div>
                """,
                unsafe_allow_html=True
            )


if page != "보안 현황":
    if st.session_state.get(
        "dashboard_auto_refresh",
        True
    ) and hasattr(st, "fragment"):

        @st.fragment(run_every="3s")
        def _live_event_fragment():
            _render_live_event_strip()

        _live_event_fragment()

    else:
        _render_live_event_strip()


# =========================================================
# 데이터 없음
# =========================================================

# 보안 현황은 각 실시간 fragment가 최신 이벤트를 직접 다시 조회하므로
# 최초 전체 렌더링 시점의 df가 비어 있어도 페이지 실행을 중단하지 않는다.
# 다른 페이지는 기존 동작을 유지한다.
if df.empty and page != "보안 현황":
    st.warning(
        "현재 수집된 보안 이벤트가 없습니다. "
        "왼쪽 시연 제어에서 정상 또는 공격 시나리오를 실행할 수 있습니다."
    )

    st.stop()


# =========================================================
# 공통 통계
# =========================================================

user_stats = make_user_stats(
    df
)

risk_order = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]

if "risk_level" in df.columns:
    risk_counts = (
        df["risk_level"]
        .value_counts()
        .reindex(
            risk_order,
            fill_value=0
        )
    )
else:
    risk_counts = pd.Series(
        [0, 0, 0, 0],
        index=risk_order
    )


# =========================================================
def load_incident_playbook(incident_id):
    try:
        response = requests.get(
            f"{API_URL}/incidents/{incident_id}/playbook",
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except Exception:
            detail = response.text

        return False, {"detail": detail}

    except Exception as error:
        return False, {"detail": str(error)}


def update_incident_playbook_step(
    incident_id,
    step_id,
    action
):
    try:
        response = requests.post(
            f"{API_URL}/incidents/{incident_id}/playbook/steps/{step_id}",
            json={
                "action": action,
                "note": None
            },
            timeout=10
        )

        if response.status_code == 200:
            return True, response.json()

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except Exception:
            detail = response.text

        return False, {"detail": detail}

    except Exception as error:
        return False, {"detail": str(error)}


def run_incident_ai_analysis(incident_id):
    try:
        response = requests.post(
            f"{API_URL}/ai-analysis/incident/{incident_id}",
            timeout=90
        )

        if response.status_code == 200:
            return response.json(), None

        try:
            detail = response.json().get(
                "detail",
                response.text
            )
        except Exception:
            detail = response.text

        return None, detail

    except Exception as error:
        return None, str(error)


# PAGE 1
# 보안 현황
# =========================================================

def _load_security_overview_state():
    df = load_event_dataframe()

    if df.empty:
        return df, pd.DataFrame(), pd.Series(
            [0, 0, 0, 0],
            index=["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        )

    user_stats = make_user_stats(
        df
    )

    risk_order = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    if "risk_level" in df.columns:
        risk_counts = (
            df["risk_level"]
            .value_counts()
            .reindex(
                risk_order,
                fill_value=0
            )
        )
    else:
        risk_counts = pd.Series(
            [0, 0, 0, 0],
            index=risk_order
        )

    return df, user_stats, risk_counts


def _overview_basic_section():
    df, _, _ = _load_security_overview_state()

    if df.empty:
        st.warning(
            "현재 수집된 보안 이벤트가 없습니다."
        )
        return

    # =====================================================
    # 기본 현황
    # =====================================================

    section_header(
        "보안 현황"
    )

    st.caption(
        "최근 수집된 보안 이벤트를 기준으로 현재 위험 상태와 "
        "우선 확인이 필요한 항목을 요약합니다."
    )

    render_kpis(
        df
    )



def _overview_visual_section():
    df, _, risk_counts = _load_security_overview_state()

    if df.empty:
        return

    # =====================================================
    # 한눈에 보는 보안 상태
    # =====================================================

    section_header(
        "한눈에 보는 보안 상태"
    )

    visual1, visual2, visual3 = st.columns(
        [1, 1, 1]
    )


    # -----------------------------------------------------
    # 위험 등급 도넛
    # -----------------------------------------------------

    with visual1:

        level_labels = {
            "LOW": "낮음",
            "MEDIUM": "주의",
            "HIGH": "높음",
            "CRITICAL": "심각"
        }

        level_colors = {
            "LOW": "#22c55e",
            "MEDIUM": "#eab308",
            "HIGH": "#f97316",
            "CRITICAL": "#ef4444"
        }

        risk_values = [
            int(risk_counts.get(level, 0))
            for level in risk_order
        ]

        risk_labels = [
            level_labels[level]
            for level in risk_order
        ]

        risk_colors = [
            level_colors[level]
            for level in risk_order
        ]

        risk_fig = go.Figure(
            data=[
                go.Pie(
                    labels=risk_labels,
                    values=risk_values,
                    hole=0.68,
                    marker=dict(
                        colors=risk_colors
                    ),
                    textinfo="percent",
                    hovertemplate=(
                        "%{label}<br>"
                        "%{value}건<br>"
                        "%{percent}"
                        "<extra></extra>"
                    )
                )
            ]
        )

        risk_fig.update_layout(
            title=dict(
                text="위험 등급 분포",
                font=dict(
                    size=15,
                    color="#e5e7eb"
                )
            ),
            annotations=[
                dict(
                    text=f"{len(df):,}<br><span style='font-size:11px'>전체 이벤트</span>",
                    x=0.5,
                    y=0.5,
                    showarrow=False,
                    font=dict(
                        size=22,
                        color="#f8fafc"
                    )
                )
            ],
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(
                color="#94a3b8"
            ),
            legend=dict(
                orientation="h",
                y=-0.08,
                x=0.5,
                xanchor="center"
            ),
            margin=dict(
                l=10,
                r=10,
                t=45,
                b=35
            ),
            height=330
        )

        risk_fig.update_layout(
            transition_duration=0
        )

        st.plotly_chart(
            risk_fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )


    # -----------------------------------------------------
    # 이벤트 유형 도넛
    # -----------------------------------------------------

    with visual2:

        if "event_type" in df.columns:

            type_series = (
                df["event_type"]
                .fillna("unknown")
                .astype(str)
                .apply(event_type_korean)
                .value_counts()
            )

            # 상위 6개만 표시하고 나머지는 기타로 묶음
            if len(type_series) > 6:

                top_types = type_series.head(6)

                other_count = int(
                    type_series.iloc[6:].sum()
                )

                type_series = top_types.copy()

                if other_count > 0:
                    type_series.loc["기타"] = other_count

        else:
            type_series = pd.Series(
                dtype=int
            )

        event_fig = go.Figure(
            data=[
                go.Pie(
                    labels=type_series.index.tolist(),
                    values=type_series.values.tolist(),
                    hole=0.68,
                    textinfo="percent",
                    hovertemplate=(
                        "%{label}<br>"
                        "%{value}건<br>"
                        "%{percent}"
                        "<extra></extra>"
                    )
                )
            ]
        )

        dominant_type = (
            str(type_series.index[0])
            if not type_series.empty
            else "-"
        )

        event_fig.update_layout(
            title=dict(
                text="이벤트 유형 분포",
                font=dict(
                    size=15,
                    color="#e5e7eb"
                )
            ),
            annotations=[
                dict(
                    text=(
                        f"{dominant_type}"
                        "<br>"
                        "<span style='font-size:10px'>최다 유형</span>"
                    ),
                    x=0.5,
                    y=0.5,
                    showarrow=False,
                    font=dict(
                        size=18,
                        color="#f8fafc"
                    )
                )
            ],
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(
                color="#94a3b8"
            ),
            legend=dict(
                orientation="h",
                y=-0.08,
                x=0.5,
                xanchor="center"
            ),
            margin=dict(
                l=10,
                r=10,
                t=45,
                b=35
            ),
            height=330
        )

        event_fig.update_layout(
            transition_duration=0
        )

        st.plotly_chart(
            event_fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )


    # -----------------------------------------------------
    # 평균 위험도 게이지
    # -----------------------------------------------------

    with visual3:

        if "risk_score" in df.columns:

            average_risk = float(
                pd.to_numeric(
                    df["risk_score"],
                    errors="coerce"
                )
                .fillna(0)
                .mean()
            )

        else:
            average_risk = 0.0


        if average_risk >= 80:
            current_status = "심각"

        elif average_risk >= 60:
            current_status = "높음"

        elif average_risk >= 24:
            current_status = "주의"

        else:
            current_status = "낮음"


        gauge_fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=average_risk,
                number={
                    "suffix": "점",
                    "font": {
                        "size": 34,
                        "color": "#f8fafc"
                    }
                },
                title={
                    "text": (
                        "최근 이벤트 평균 위험도"
                        f"<br><span style='font-size:13px'>현재 상태: {current_status}</span>"
                    ),
                    "font": {
                        "size": 15,
                        "color": "#e5e7eb"
                    }
                },
                gauge={
                    "axis": {
                        "range": [0, 100],
                        "tickcolor": "#64748b"
                    },
                    "bar": {
                        "color": "#3b82f6",
                        "thickness": 0.25
                    },
                    "bgcolor": "#111827",
                    "borderwidth": 0,
                    "steps": [
                        {
                            "range": [0, 24],
                            "color": "#123525"
                        },
                        {
                            "range": [24, 60],
                            "color": "#3d3510"
                        },
                        {
                            "range": [60, 80],
                            "color": "#42250e"
                        },
                        {
                            "range": [80, 100],
                            "color": "#41191d"
                        }
                    ],
                    "threshold": {
                        "line": {
                            "color": "#ef4444",
                            "width": 3
                        },
                        "thickness": 0.75,
                        "value": 80
                    }
                }
            )
        )

        gauge_fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(
                color="#94a3b8"
            ),
            margin=dict(
                l=25,
                r=25,
                t=55,
                b=10
            ),
            height=330
        )

        gauge_fig.update_layout(
            transition_duration=0
        )

        st.plotly_chart(
            gauge_fig,
            use_container_width=True,
            config={
                "displayModeBar": False
            }
        )


    st.caption(
        "※ 현재 화면의 시각화는 최근 로딩된 이벤트를 기준으로 계산됩니다."
    )




def _overview_priority_section():
    df, _, _ = _load_security_overview_state()

    if df.empty:
        return

    # =====================================================
    # 즉시 확인 필요
    # =====================================================

    section_header(
        "즉시 확인 필요"
    )

    priority_left, priority_right = st.columns(
        [1.15, 1]
    )


    # -----------------------------------------------------
    # 고위험 이벤트 TOP 5
    # -----------------------------------------------------

    with priority_left:

        st.markdown(
            "**위험도 상위 이벤트 5건**"
        )

        if (
            "risk_score" in df.columns
            and not df.empty
        ):

            top_events = (
                df.sort_values(
                    "risk_score",
                    ascending=False
                )
                .head(5)
                .copy()
            )

            top_event_columns = [
                column
                for column in [
                    "timestamp",
                    "user",
                    "event_type",
                    "risk_score",
                    "risk_level"
                ]
                if column in top_events.columns
            ]

            top_events = top_events[
                top_event_columns
            ].copy()

            if "timestamp" in top_events.columns:
                top_events["timestamp"] = (
                    top_events["timestamp"]
                    .apply(
                        lambda value: (
                            value.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                            if (
                                value is not None
                                and not pd.isna(value)
                                and hasattr(
                                    value,
                                    "strftime"
                                )
                            )
                            else "-"
                        )
                    )
                )

            if "event_type" in top_events.columns:
                top_events["event_type"] = (
                    top_events["event_type"]
                    .astype(str)
                    .apply(event_type_korean)
                )

            top_events = top_events.rename(
                columns={
                    "timestamp": "발생 시간",
                    "user": "사용자",
                    "event_type": "이벤트",
                    "risk_score": "위험도",
                    "risk_level": "등급"
                }
            )

            st.dataframe(
                top_events,
                use_container_width=True,
                hide_index=True,
                height=245
            )

        else:
            st.info(
                "표시할 위험 이벤트가 없습니다."
            )


    # -----------------------------------------------------
    # 위험 사용자 TOP 5
    # -----------------------------------------------------

    with priority_right:

        st.markdown(
            "**현재 위험 사용자 TOP 5**"
        )

        if (
            "user" in df.columns
            and "risk_score" in df.columns
        ):

            user_summary = (
                df.groupby("user")
                .agg(
                    최고위험도=(
                        "risk_score",
                        "max"
                    ),
                    평균위험도=(
                        "risk_score",
                        "mean"
                    ),
                    이벤트수=(
                        "risk_score",
                        "count"
                    )
                )
                .reset_index()
            )

            user_summary = (
                user_summary
                .sort_values(
                    [
                        "최고위험도",
                        "평균위험도"
                    ],
                    ascending=False
                )
                .head(5)
            )

            user_summary[
                "평균위험도"
            ] = (
                user_summary[
                    "평균위험도"
                ]
                .round(2)
            )

            user_summary = user_summary.rename(
                columns={
                    "user": "사용자"
                }
            )

            st.dataframe(
                user_summary,
                use_container_width=True,
                hide_index=True,
                height=245
            )

        else:
            st.info(
                "표시할 사용자 데이터가 없습니다."
            )




def _overview_behavior_section():
    df, _, _ = _load_security_overview_state()

    if df.empty:
        return

    # =====================================================
    # 행동 변화 검증 현황
    # =====================================================

    section_header(
        "행동 변화 검증 현황"
    )

    st.caption(
        "새 IP·프로세스·장치가 현재 정상 기준선에 반영 가능한 상태인지 요약합니다."
    )

    behavior_status_by_target = {}

    if "reasons" in df.columns:

        behavior_pattern = re.compile(
            r"행동 변화 검증:\s*([^/]+?)\s*/\s*"
            r"(OBSERVING|ACCEPTED|REJECTED)"
        )

        # df는 최신순 정렬 상태이므로
        # 동일 대상은 가장 최근 상태만 사용
        for reason_text in (
            df["reasons"]
            .fillna("")
            .astype(str)
        ):

            matches = behavior_pattern.findall(
                reason_text
            )

            for target, status in matches:

                target = target.strip()

                if (
                    target
                    and target
                    not in behavior_status_by_target
                ):
                    behavior_status_by_target[
                        target
                    ] = status


    observing_count = sum(
        1
        for status
        in behavior_status_by_target.values()
        if status == "OBSERVING"
    )

    accepted_count = sum(
        1
        for status
        in behavior_status_by_target.values()
        if status == "ACCEPTED"
    )

    rejected_count = sum(
        1
        for status
        in behavior_status_by_target.values()
        if status == "REJECTED"
    )


    behavior1, behavior2, behavior3 = st.columns(
        3
    )

    with behavior1:
        st.metric(
            "관찰 중",
            observing_count,
            help="아직 정상 여부를 판단하기 위해 관찰 중인 신규 행동"
        )

    with behavior2:
        st.metric(
            "정상 승인",
            accepted_count,
            help="검증을 통과해 정상 기준선 학습이 허용된 행동"
        )

    with behavior3:
        st.metric(
            "학습 제외",
            rejected_count,
            help="위험 맥락이 확인되어 정상 기준선 학습에서 제외된 행동"
        )


    if (
        observing_count
        + accepted_count
        + rejected_count
        == 0
    ):
        st.info(
            "최근 이벤트에는 행동 변화 검증 기록이 없습니다."
        )




def _overview_alerts_recent_section():
    df, _, _ = _load_security_overview_state()

    if df.empty:
        return

    # =====================================================
    # 기존 주요 경보
    # =====================================================

    section_header(
        "주요 보안 경보"
    )

    render_alert_table(
        df,
        height=260
    )


    # =====================================================
    # 최근 이벤트
    # =====================================================

    section_header(
        "최근 보안 이벤트"
    )

    render_timeline(
        df.head(50),
        height=330
    )




def _overview_performance_section():
    # =====================================================
    # 시스템 성능 / 운영 참고
    # =====================================================

    section_header(
        "시스템 성능 / 운영 참고"
    )

    st.caption(
        "사고 판단과 직접 관련된 지표가 아니라 "
        "현재 수집·API 상태를 확인하기 위한 운영 참고 정보입니다."
    )

    performance = load_event_metrics()

    perf1, perf2, perf3, perf4 = st.columns(4)

    with perf1:
        st.metric(
            "최근 60초 이벤트",
            performance[
                "recent_60s_events"
            ]
        )

    with perf2:
        st.metric(
            "관측 EPS",
            f"{performance['observed_eps']:.2f}",
            help=(
                "최근 60초 동안 실제 조회된 이벤트 수를 "
                "60으로 나눈 관측값입니다."
            )
        )

    with perf3:
        latency = performance[
            "api_latency_ms"
        ]

        st.metric(
            "/events 응답 지연",
            (
                f"{latency:.1f} ms"
                if latency is not None
                else "연결 실패"
            )
        )

    with perf4:
        st.metric(
            "현재 조회 이벤트",
            performance[
                "loaded_events"
            ],
            help="대시보드가 현재 분석 중인 최신 이벤트 수"
        )

    st.caption(
        "※ EPS와 응답 지연은 현재 실행 환경에서 직접 관측한 값이며 "
        "부하 테스트 최대 처리량을 의미하지 않습니다."
    )


def _render_security_overview_live_body():
    # 모든 이벤트 기반 요소를 한 번의 렌더 주기로 동기화한다.
    # 여러 fragment가 서로 다른 시점에 번쩍이는 현상을 줄이기 위한 구조다.
    _render_live_critical_alert()
    _render_live_event_strip()
    _overview_basic_section()
    _overview_visual_section()
    _overview_priority_section()
    _overview_behavior_section()
    _overview_alerts_recent_section()
    _overview_performance_section()


def render_security_overview_page():
    auto_refresh = st.session_state.get(
        "dashboard_auto_refresh",
        True
    )

    if auto_refresh and hasattr(st, "fragment"):

        @st.fragment(run_every="3s")
        def _security_overview_synced_fragment():
            _render_security_overview_live_body()

        _security_overview_synced_fragment()

    else:
        _render_security_overview_live_body()


if page == "보안 현황":
    # 사이드바와 페이지 헤더는 고정한다.
    # 이벤트 기반 본문은 하나의 fragment에서 동시에 갱신해
    # 여러 영역이 따로 번쩍이는 현상을 최소화한다.
    render_security_overview_page()



# =========================================================
# PAGE 2
# 이벤트 모니터링
# =========================================================

elif page == "이벤트 모니터링":

    section_header(
        "이벤트 필터"
    )

    filter1, filter2, filter3 = (
        st.columns(3)
    )


    with filter1:
        level_options = [
            "전체"
        ]

        if "risk_level" in df.columns:
            level_options += sorted(
                [
                    str(value)
                    for value
                    in df["risk_level"]
                    .dropna()
                    .unique()
                ]
            )

        selected_level = st.selectbox(
            "위험 등급",
            level_options
        )


    with filter2:
        user_options = [
            "전체"
        ]

        if "user" in df.columns:
            user_options += sorted(
                [
                    str(value)
                    for value
                    in df["user"]
                    .dropna()
                    .unique()
                ]
            )

        selected_user = st.selectbox(
            "사용자",
            user_options
        )


    with filter3:
        type_options = [
            "전체"
        ]

        if "event_type" in df.columns:
            raw_types = sorted(
                [
                    str(value)
                    for value
                    in df["event_type"]
                    .dropna()
                    .unique()
                ]
            )

            display_type_map = {
                event_type_korean(value): value
                for value in raw_types
            }

            type_options += list(
                display_type_map.keys()
            )

        else:
            display_type_map = {}

        selected_type = st.selectbox(
            "이벤트 유형",
            type_options
        )


    search_text = st.text_input(
        "검색",
        placeholder=(
            "사용자, IP, 파일명, 프로세스명 검색"
        )
    )


    filtered_df = df.copy()


    if (
        selected_level != "전체"
        and "risk_level" in filtered_df.columns
    ):
        filtered_df = filtered_df[
            filtered_df["risk_level"]
            == selected_level
        ]


    if (
        selected_user != "전체"
        and "user" in filtered_df.columns
    ):
        filtered_df = filtered_df[
            filtered_df["user"].astype(str)
            == selected_user
        ]


    if (
        selected_type != "전체"
        and "event_type" in filtered_df.columns
    ):
        raw_type = display_type_map.get(
            selected_type,
            selected_type
        )

        filtered_df = filtered_df[
            filtered_df["event_type"].astype(str)
            == raw_type
        ]


    if search_text.strip():
        search_text_lower = (
            search_text
            .strip()
            .lower()
        )

        search_columns = [
            column
            for column in [
                "user",
                "source_ip",
                "file_name",
                "process_name"
            ]
            if column in filtered_df.columns
        ]

        mask = pd.Series(
            False,
            index=filtered_df.index
        )

        for column in search_columns:
            mask = (
                mask
                | filtered_df[column]
                .fillna("")
                .astype(str)
                .str.lower()
                .str.contains(
                    search_text_lower,
                    regex=False
                )
            )

        filtered_df = filtered_df[
            mask
        ]


    section_header(
        "모니터링 현황"
    )

    total_filtered = len(
        filtered_df
    )

    critical_filtered = (
        len(
            filtered_df[
                filtered_df["risk_level"]
                == "CRITICAL"
            ]
        )
        if "risk_level" in filtered_df.columns
        else 0
    )

    high_filtered = (
        len(
            filtered_df[
                filtered_df["risk_level"]
                == "HIGH"
            ]
        )
        if "risk_level" in filtered_df.columns
        else 0
    )

    filtered_users = (
        filtered_df["user"].nunique()
        if "user" in filtered_df.columns
        else 0
    )

    m1, m2, m3, m4 = (
        st.columns(4)
    )

    monitoring_cards = [
        (
            m1,
            "조회 이벤트",
            total_filtered,
            "현재 필터 조건"
        ),
        (
            m2,
            "CRITICAL",
            critical_filtered,
            "긴급 위험 이벤트"
        ),
        (
            m3,
            "HIGH",
            high_filtered,
            "고위험 이벤트"
        ),
        (
            m4,
            "사용자",
            filtered_users,
            "조회된 사용자"
        )
    ]

    for (
        column,
        label,
        value,
        foot
    ) in monitoring_cards:

        with column:
            html = (
                '<div class="kpi-card">'
                f'<div class="kpi-label">{label}</div>'
                f'<div class="kpi-value">{value:,}</div>'
                f'<div class="kpi-foot">{foot}</div>'
                '</div>'
            )

            st.markdown(
                html,
                unsafe_allow_html=True
            )


    section_header(
        "보안 이벤트 로그"
    )

    if filtered_df.empty:
        st.info(
            "현재 조건에 해당하는 이벤트가 없습니다."
        )

    else:
        render_timeline(
            filtered_df,
            height=600
        )




        # ---------------------------------------------------------
        # Behavior Change Verification Dashboard
        # ---------------------------------------------------------

        section_header("행동 변화 검증")

        st.caption(
            "새로운 IP·프로세스·장치를 즉시 정상으로 학습하지 않고 "
            "관찰 후 ACCEPTED 또는 REJECTED 상태로 판정합니다."
        )

        behavior_source = filtered_df.copy()

        behavior_source = behavior_source[
            behavior_source["reasons"]
            .fillna("")
            .astype(str)
            .str.contains(
                "행동 변화 검증:",
                regex=False
            )
        ]

        if behavior_source.empty:
            st.info(
                "현재 표시 중인 이벤트에는 행동 변화 검증 결과가 없습니다."
            )

        else:
            behavior_source = behavior_source.sort_values(
                "timestamp",
                ascending=False
            )

            behavior_options = behavior_source["id"].tolist()

            behavior_labels = {}

            for _, row in behavior_source.iterrows():
                event_id = int(row["id"])

                behavior_labels[event_id] = (
                    f"#{event_id} · "
                    f"{display_value(row.get('user'))} · "
                    f"{event_type_korean(row.get('event_type'))} · "
                    f"{display_value(row.get('risk_level'))}"
                )

            selected_behavior_event_id = st.selectbox(
                "행동 변화 검증 이벤트",
                behavior_options,
                format_func=lambda event_id: behavior_labels.get(
                    event_id,
                    str(event_id)
                ),
                key="behavior_change_event_selector"
            )

            selected_behavior_row = behavior_source[
                behavior_source["id"]
                == selected_behavior_event_id
            ].iloc[0]

            behavior_reason_text = str(
                selected_behavior_row.get(
                    "reasons",
                    ""
                )
                or ""
            )

            behavior_items = []

            for reason in behavior_reason_text.split(","):
                reason = reason.strip()

                if not reason.startswith("행동 변화 검증:"):
                    continue

                body = reason.replace(
                    "행동 변화 검증:",
                    "",
                    1
                ).strip()

                parts = [
                    part.strip()
                    for part in body.split(" / ", 2)
                ]

                if len(parts) >= 2:
                    behavior_items.append({
                        "target": parts[0],
                        "status": parts[1].upper(),
                        "reason": (
                            parts[2]
                            if len(parts) >= 3
                            else "-"
                        )
                    })

            observing_count = sum(
                1
                for item in behavior_items
                if item["status"] == "OBSERVING"
            )

            accepted_count = sum(
                1
                for item in behavior_items
                if item["status"] == "ACCEPTED"
            )

            rejected_count = sum(
                1
                for item in behavior_items
                if item["status"] == "REJECTED"
            )

            bc1, bc2, bc3 = st.columns(3)

            with bc1:
                st.metric(
                    "관찰 중",
                    observing_count
                )

            with bc2:
                st.metric(
                    "정상 승인",
                    accepted_count
                )

            with bc3:
                st.metric(
                    "학습 제외",
                    rejected_count
                )

            for item in behavior_items:
                message = (
                    f"{item['status']} · "
                    f"{item['target']}\n\n"
                    f"{item['reason']}"
                )

                if item["status"] == "REJECTED":
                    st.error(message)

                elif item["status"] == "ACCEPTED":
                    st.success(message)

                else:
                    st.warning(message)

            st.caption(
                "OBSERVING = 정상 여부 관찰 중 · "
                "ACCEPTED = 정상 변화로 승인하여 기준선 학습 허용 · "
                "REJECTED = 위험 맥락 확인으로 정상 기준선 학습 제외"
            )


        # ---------------------------------------------------------
        # Explainable Risk Score
        # ---------------------------------------------------------
        section_header("Explainable Risk Score")
        st.caption(
            "탐지 엔진이 최종 Event Risk를 어떻게 구성했는지 "
            "저장된 실제 계산 근거를 기준으로 설명합니다."
        )

        explainable_source = filtered_df.copy()
        if not explainable_source.empty:
            explainable_source = explainable_source.sort_values(
                "timestamp",
                ascending=False
            )

            explainable_options = explainable_source["id"].tolist()
            explainable_labels = {}

            for _, explainable_row in explainable_source.iterrows():
                explainable_event_id = int(explainable_row["id"])
                explainable_process = display_value(
                    explainable_row.get("process_name")
                )
                explainable_user = display_value(
                    explainable_row.get("user")
                )
                explainable_level = display_value(
                    explainable_row.get("risk_level")
                )
                explainable_score = display_value(
                    explainable_row.get("risk_score")
                )
                explainable_labels[explainable_event_id] = (
                    f"#{explainable_event_id} · {explainable_user} · "
                    f"{explainable_process} · {explainable_level} · "
                    f"Risk {explainable_score}"
                )

            selected_explainable_event_id = st.selectbox(
                "분석할 이벤트",
                explainable_options,
                format_func=lambda event_id: explainable_labels.get(
                    event_id,
                    str(event_id)
                ),
                key="explainable_risk_event_selector"
            )

            explanation_ok, explanation = load_risk_explanation(
                selected_explainable_event_id
            )

            if explanation_ok:
                final_score = float(explanation.get("final_score", 0) or 0)
                final_level = str(explanation.get("risk_level", "-"))
                anomaly_score = float(explanation.get("anomaly_score", 0) or 0)

                components = explanation.get("components", []) or []
                component_map = {
                    str(component.get("key", "")): component
                    for component in components
                    if isinstance(component, dict)
                }

                baseline_component = component_map.get("personal_baseline", {})
                peer_component = component_map.get("peer_group", {})
                adaptive_component = component_map.get("adaptive", {})

                baseline_score = float(
                    baseline_component.get("source_score", 0) or 0
                )
                peer_score = float(
                    peer_component.get("source_score", 0) or 0
                )
                score_before_floor = float(
                    explanation.get("score_before_floor", 0) or 0
                )
                floor_applied = bool(
                    explanation.get("floor_applied", False)
                )
                floor_reason = explanation.get("floor_reason")

                er1, er2, er3, er4 = st.columns(4)
                er1.metric("최종 Event Risk", f"{final_score:.2f}")
                er2.metric("위험 등급", final_level)
                er3.metric("Isolation Forest", f"{anomaly_score:.2f}")
                er4.metric("개인 기준선", f"{baseline_score:.2f}")

                breakdown_rows = []

                labels = {
                    "base": "Rule + ML 기본 위험도",
                    "personal_baseline": "Adaptive Personal Baseline",
                    "sequence": "Sequence Detection",
                    "peer_group": "Peer Group UEBA",
                    "adaptive": "Adaptive 정상 패턴 보정",
                }

                for key in [
                    "base",
                    "personal_baseline",
                    "sequence",
                    "peer_group",
                    "adaptive",
                ]:
                    component = component_map.get(key, {})
                    source_score = float(
                        component.get("source_score", 0) or 0
                    )
                    contribution = float(
                        component.get("contribution", 0) or 0
                    )

                    if key == "adaptive":
                        displayed_contribution = -abs(contribution)
                    else:
                        displayed_contribution = contribution

                    description = str(
                        component.get("description", "") or ""
                    )

                    if key == "peer_group":
                        if component.get("guard_passed") is False:
                            description = (
                                f"Peer Score {source_score:.2f}의 행동 차이는 "
                                "관찰됐지만 Peer Risk Guard 미통과로 "
                                "최종 Risk에는 미반영"
                            )
                        elif component.get("guard_passed") is True:
                            description = (
                                "Peer Risk Guard 통과 · "
                                f"최종 위험도에 {contribution:.2f}점 반영"
                            )

                    breakdown_rows.append({
                        "구성 요소": labels[key],
                        "원본 점수": round(source_score, 2),
                        "최종 기여": round(displayed_contribution, 2),
                        "설명": description,
                    })

                breakdown = pd.DataFrame(breakdown_rows)

                st.dataframe(
                    breakdown,
                    use_container_width=True,
                    hide_index=True
                )

                if floor_applied:
                    floor_text = (
                        f"안전장치 적용 전 Risk {score_before_floor:.2f} → "
                        f"Floor 적용 → 최종 Event Risk {final_score:.2f}"
                    )
                    if floor_reason:
                        floor_text += f" · {floor_reason}"
                    st.caption(floor_text)
                else:
                    st.caption(
                        f"안전장치 적용 전 Risk {score_before_floor:.2f} → "
                        f"Floor 미적용 → 최종 Event Risk {final_score:.2f}"
                    )

                explanation_reasons = (
                    explanation.get("reasons", []) or []
                )
                if explanation_reasons:
                    st.markdown("**왜 이 점수인가?**")
                    for reason in explanation_reasons:
                        st.markdown(f"- {reason}")

                if (
                    peer_component
                    and peer_component.get("guard_passed") is False
                ):
                    st.markdown("**Peer Risk Guard**")
                    st.markdown(
                        f"- Peer Group에서는 {peer_score:.2f}점의 행동 차이가 "
                        "관찰됐지만 강한 Peer 증거 조건을 충족하지 않아 "
                        "최종 Event Risk에는 반영하지 않았습니다."
                    )

                if adaptive_component:
                    adaptive_applied = bool(
                        adaptive_component.get("applied", False)
                    )
                    adaptive_confidence = str(
                        adaptive_component.get(
                            "confidence_level",
                            "-"
                        )
                    )
                    if not adaptive_applied:
                        st.markdown("**Adaptive 정상 패턴 보정**")
                        st.markdown(
                            f"- 개인 기준선 엔진 학습 상태: "
                            f"{adaptive_confidence}"
                        )
                        st.markdown(
                            "- 현재 이벤트에는 Adaptive 위험도 감점이 적용되지 않았습니다."
                        )
                        st.caption(
                            "※ LEARNING은 개인 기준선 엔진의 데이터 축적 상태를 의미합니다. "
                            "행동 변화 검증의 OBSERVING / ACCEPTED / REJECTED와는 별도 상태입니다. "
                            "REJECTED된 신규 행동은 정상 기준선 학습 대상에서 제외됩니다."
                        )
            else:
                detail = explanation.get("detail", "")
                st.info(
                    detail
                    or "이 이벤트에는 저장된 Explainable Risk 데이터가 없습니다. "
                       "기능 도입 이후 생성된 새 이벤트부터 정확한 구성 점수를 확인할 수 있습니다."
                )

# =========================================================
# PAGE 3
# 보안 사고 분석
# =========================================================

elif page == "보안 사고 분석":

    section_header(
        "Incident Correlation"
    )

    incidents_ok, incidents = load_incidents()

    if incidents_ok and incidents:

        priority_map = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }

        incidents = sorted(
            incidents,
            key=lambda item: (
                priority_map.get(
                    str(item.get("severity", "")).upper(),
                    0
                ),
                float(item.get("correlation_score", 0) or 0),
                str(item.get("last_seen", ""))
            ),
            reverse=True
        )

        filter_col1, filter_col2, filter_col3 = st.columns(
            [1, 1, 2]
        )

        with filter_col1:
            incident_level_filter = st.selectbox(
                "사고 심각도",
                [
                    "전체",
                    "CRITICAL",
                    "HIGH",
                    "MEDIUM",
                    "LOW"
                ],
                key="correlated_incident_level_filter"
            )

        with filter_col2:
            incident_status_filter = st.selectbox(
                "상태",
                [
                    "전체",
                    "OPEN",
                    "CLOSED"
                ],
                key="correlated_incident_status_filter"
            )

        with filter_col3:
            st.caption(
                "여러 보안 이벤트를 사용자 · 시간 · 공격 단계 기준으로 "
                "상관분석하여 하나의 조사 가능한 사고로 재구성합니다."
            )

        filtered_incidents = []

        for item in incidents:
            severity = str(
                item.get("severity", "-")
            ).upper()

            status = str(
                item.get("status", "-")
            ).upper()

            if (
                incident_level_filter != "전체"
                and severity != incident_level_filter
            ):
                continue

            if (
                incident_status_filter != "전체"
                and status != incident_status_filter
            ):
                continue

            filtered_incidents.append(item)

        if filtered_incidents:

            incident_options = {}

            for item in filtered_incidents:
                incident_id = item.get(
                    "incident_id",
                    item.get("id", "-")
                )

                severity = item.get(
                    "severity",
                    "-"
                )

                status = item.get(
                    "status",
                    "-"
                )

                user = item.get(
                    "user",
                    "-"
                )

                title = item.get(
                    "title",
                    item.get(
                        "incident_type",
                        "보안 사고"
                    )
                )

                correlation_score = item.get(
                    "correlation_score",
                    0
                )

                label = (
                    f"{incident_id}  |  "
                    f"{severity}  |  "
                    f"{status}  |  "
                    f"{user}  |  "
                    f"Correlation {correlation_score}  |  "
                    f"{title}"
                )

                incident_options[
                    label
                ] = item

            incident_labels = list(
                incident_options.keys()
            )

            target_incident_id = st.session_state.pop(
                "target_incident_id",
                None
            )

            target_index = 0

            if target_incident_id is not None:
                for index, label in enumerate(
                    incident_labels
                ):
                    target_item = incident_options[
                        label
                    ]
                    target_item_id = target_item.get(
                        "incident_id",
                        target_item.get("id")
                    )

                    if (
                        str(target_item_id)
                        == str(target_incident_id)
                    ):
                        target_index = index
                        break

                # 기존 selectbox 상태가 있으면 제거해 index 적용 보장
                st.session_state.pop(
                    "correlated_incident_select",
                    None
                )

            selected_incident_label = st.selectbox(
                "분석할 보안 사고를 선택하세요.",
                incident_labels,
                index=target_index,
                key="correlated_incident_select"
            )

            selected_incident_summary = incident_options[
                selected_incident_label
            ]

            selected_incident_id = selected_incident_summary.get(
                "incident_id",
                selected_incident_summary.get("id")
            )

            detail_ok, incident = load_incident_detail(
                selected_incident_id
            )

            if not detail_ok:
                incident = selected_incident_summary

            incident_id = incident.get(
                "incident_id",
                incident.get("id", "-")
            )

            incident_title = incident.get(
                "title",
                incident.get(
                    "incident_type",
                    "보안 사고"
                )
            )

            incident_type = incident.get(
                "incident_type",
                "-"
            )

            incident_user = incident.get(
                "user",
                "-"
            )

            incident_status = str(
                incident.get(
                    "status",
                    "OPEN"
                )
            ).upper()

            incident_severity = str(
                incident.get(
                    "severity",
                    "-"
                )
            ).upper()

            correlation_score = float(
                incident.get(
                    "correlation_score",
                    0
                ) or 0
            )

            storyline = incident.get(
                "storyline",
                []
            ) or []

            related_event_ids = incident.get(
                "related_event_ids",
                incident.get(
                    "event_ids",
                    []
                )
            ) or []

            if not related_event_ids and storyline:
                related_event_ids = [
                    step.get("event_id")
                    for step in storyline
                    if step.get("event_id") is not None
                ]

            event_count = int(
                incident.get(
                    "event_count",
                    len(related_event_ids)
                ) or 0
            )

            event_lookup = {}

            if "id" in df.columns:
                for _, event_row in df.iterrows():
                    event_lookup[
                        str(event_row.get("id"))
                    ] = event_row

            max_event_risk_score = 0.0
            max_event_risk_level = "-"

            max_risk_event = None

            for related_event_id in related_event_ids:
                matched_event = event_lookup.get(
                    str(related_event_id)
                )

                if matched_event is None:
                    continue

                try:
                    candidate_score = float(
                        matched_event.get(
                            "risk_score",
                            0
                        ) or 0
                    )
                except (TypeError, ValueError):
                    candidate_score = 0.0

                if (
                    max_risk_event is None
                    or candidate_score > max_event_risk_score
                ):
                    max_event_risk_score = candidate_score
                    max_event_risk_level = str(
                        matched_event.get(
                            "risk_level",
                            "-"
                        )
                    )
                    max_risk_event = matched_event

            stage_count = int(
                incident.get(
                    "stage_count",
                    len(storyline)
                ) or 0
            )

            first_seen = incident.get(
                "start_time",
                incident.get(
                    "first_seen",
                    "-"
                )
            )

            last_seen = incident.get(
                "end_time",
                incident.get(
                    "last_seen",
                    "-"
                )
            )

            incident_html = (
                f'<div class="incident-correlation-shell">'
                '<div class="incident-correlation-top">'
                '<div>'
                f'<div class="incident-correlation-id">{safe_html(incident_id)}</div>'
                f'<div class="incident-correlation-title">{safe_html(incident_title)}</div>'
                '<div class="incident-correlation-meta">'
                f'사용자 {safe_html(incident_user)} · '
                f'{safe_html(incident_type)} · '
                f'{safe_html(format_timestamp(first_seen))} ~ '
                f'{safe_html(format_timestamp(last_seen))}'
                '</div>'
                '</div>'
                '<div style="text-align:right;">'
                f'<div class="incident-status-badge">{safe_html(incident_severity)} · {safe_html(incident_status)}</div>'
                '<div class="incident-correlation-meta">'
                f'Correlation {correlation_score:.0f}'
                '</div>'
                '</div>'
                '</div>'
                '</div>'
            )

            st.markdown(
                incident_html,
                unsafe_allow_html=True
            )

            k1, k2, k3, k4 = st.columns(4)

            incident_cards = [
                (
                    k1,
                    "Correlation Score",
                    f"{correlation_score:.0f}",
                    "다중 이벤트 상관분석"
                ),
                (
                    k2,
                    "공격 단계",
                    f"{stage_count}",
                    "Storyline 단계 수"
                ),
                (
                    k3,
                    "연관 이벤트",
                    f"{event_count}",
                    "사고에 연결된 이벤트"
                ),
                (
                    k4,
                    "최대 Event Risk",
                    f"{max_event_risk_score:.2f}",
                    str(max_event_risk_level)
                )
            ]

            for column, label, value, foot in incident_cards:
                with column:
                    st.markdown(
                        (
                            '<div class="incident-kpi">'
                            f'<div class="incident-kpi-label">{safe_html(label)}</div>'
                            f'<div class="incident-kpi-value">{safe_html(value)}</div>'
                            f'<div class="incident-kpi-foot">{safe_html(foot)}</div>'
                            '</div>'
                        ),
                        unsafe_allow_html=True
                    )

            section_header(
                "Attack Storyline"
            )

            st.caption(
                "Sequence Detection이 실시간 공격 순서를 점수화한다면, "
                "Incident Correlation은 저장된 여러 이벤트를 조사 가능한 "
                "공격 스토리로 재구성합니다."
            )

            if storyline:

                storyline_parts = [
                    '<div class="storyline-shell">'
                ]

                for index, step in enumerate(
                    storyline,
                    start=1
                ):

                    stage = step.get(
                        "stage",
                        step.get(
                            "stage_name",
                            step.get(
                                "name",
                                "SECURITY_EVENT"
                            )
                        )
                    )

                    description = step.get(
                        "description",
                        step.get(
                            "detail",
                            event_type_korean(
                                step.get(
                                    "event_type",
                                    "-"
                                )
                            )
                        )
                    )

                    event_id = step.get(
                        "event_id",
                        "-"
                    )

                    timestamp = step.get(
                        "timestamp",
                        "-"
                    )

                    matched_story_event = event_lookup.get(
                        str(event_id)
                    )

                    if matched_story_event is not None:
                        event_risk = display_value(
                            matched_story_event.get(
                                "risk_score"
                            )
                        )

                        risk_level_step = display_value(
                            matched_story_event.get(
                                "risk_level"
                            )
                        )
                    else:
                        event_risk = step.get(
                            "risk_score",
                            step.get(
                                "event_risk_score",
                                "-"
                            )
                        )

                        risk_level_step = step.get(
                            "risk_level",
                            step.get(
                                "event_risk_level",
                                "-"
                            )
                        )

                    file_name = step.get(
                        "file_name"
                    )

                    process_name = step.get(
                        "process_name"
                    )

                    extra_parts = []

                    if file_name:
                        extra_parts.append(
                            f"파일 {file_name}"
                        )

                    if process_name:
                        extra_parts.append(
                            f"프로세스 {process_name}"
                        )

                    extra_text = (
                        " · ".join(extra_parts)
                    )

                    mitre_id = step.get(
                        "mitre_technique_id"
                    )

                    mitre_name = step.get(
                        "mitre_technique_name",
                        "ATT&CK 미확정"
                    )

                    mitre_tactic = step.get(
                        "mitre_tactic",
                        "Evidence Only"
                    )

                    mitre_confidence = step.get(
                        "mitre_confidence",
                        "NONE"
                    )

                    mitre_note = step.get(
                        "mitre_note",
                        ""
                    )

                    detail_text = (
                        f"{description} · Event #{event_id} · "
                        f"{format_timestamp(timestamp)}"
                    )

                    if extra_text:
                        detail_text += (
                            f" · {extra_text}"
                        )

                    mitre_label = (
                        f"{mitre_id} · {mitre_name}"
                        if mitre_id
                        else mitre_name
                    )

                    storyline_parts.append(
                        '<div class="storyline-step">'
                        f'<div class="storyline-index">{index:02d}</div>'
                        '<div>'
                        f'<div class="storyline-name">{safe_html(stage)}</div>'
                        f'<div class="storyline-detail">{safe_html(detail_text)}</div>'
                        '<div class="mitre-row">'
                        f'<span class="mitre-badge">{safe_html(mitre_label)}</span>'
                        f'<span class="mitre-tactic">{safe_html(mitre_tactic)}</span>'
                        f'<span class="mitre-confidence">근거 {safe_html(mitre_confidence)}</span>'
                        '</div>'
                        f'<div class="storyline-detail">{safe_html(mitre_note)}</div>'
                        '</div>'
                        '<div class="storyline-risk">'
                        f'{safe_html(risk_level_step)}<br>'
                        f'Risk {safe_html(event_risk)}'
                        '</div>'
                        '</div>'
                    )

                    if index < len(storyline):
                        storyline_parts.append(
                            '<div class="storyline-arrow">↓</div>'
                        )

                storyline_parts.append(
                    '</div>'
                )

                st.markdown(
                    "".join(storyline_parts),
                    unsafe_allow_html=True
                )

            else:
                st.info(
                    "이 사고에 구성된 Attack Storyline이 없습니다."
                )

            section_header(
                "AI SOC Analyst"
            )

            st.caption(
                "OpenAI API가 선택한 Incident의 Storyline, Event Risk, "
                "MITRE ATT&CK, Dynamic User Risk를 함께 해석합니다. "
                "AI는 탐지 점수를 결정하지 않고 조사 의사결정을 보조합니다."
            )

            ai_state_key = f"incident_ai_result_{incident_id}"

            if st.button(
                "Incident 전체 AI 분석 실행",
                key=f"incident_ai_button_{incident_id}",
                use_container_width=True
            ):
                with st.spinner(
                    "OpenAI API가 Incident 전체 증거를 분석하고 있습니다..."
                ):
                    ai_response, ai_error = run_incident_ai_analysis(
                        incident_id
                    )

                if ai_error:
                    st.error(f"AI SOC 분석 실패: {ai_error}")
                else:
                    st.session_state[ai_state_key] = ai_response.get(
                        "ai_analysis",
                        {}
                    )

            incident_ai = st.session_state.get(ai_state_key)

            if incident_ai:
                st.markdown("#### 사고 요약")
                st.info(incident_ai.get("incident_summary", "-"))

                st.markdown("#### 가능한 위협 시나리오")
                st.write(incident_ai.get("threat_scenario", "-"))

                ai_left, ai_right = st.columns(2)

                with ai_left:
                    st.markdown("#### 확인된 사실")
                    for item in incident_ai.get("confirmed_facts", []) or []:
                        st.markdown(f"- {item}")

                with ai_right:
                    st.markdown("#### 아직 확인되지 않은 사실")
                    for item in incident_ai.get("uncertainties", []) or []:
                        st.markdown(f"- {item}")

                st.markdown("#### 공격 흐름 해석")
                st.write(incident_ai.get("attack_flow_analysis", "-"))

                mitre_analysis = incident_ai.get("mitre_analysis", []) or []

                if mitre_analysis:
                    st.markdown("#### MITRE ATT&CK 해석")

                    for item in mitre_analysis:
                        st.markdown(
                            f"**{item.get('technique_id', '미확정')}** · "
                            f"{item.get('interpretation', '')}"
                        )

                report_left, report_right = st.columns(2)

                with report_left:
                    st.markdown("#### 핵심 증거")

                    for item in incident_ai.get("key_evidence", []) or []:
                        st.markdown(f"- {item}")

                    st.markdown("#### 우선 조사 항목")

                    for index, item in enumerate(
                        incident_ai.get("investigation_priorities", []) or [],
                        start=1
                    ):
                        st.markdown(f"{index}. {item}")

                with report_right:
                    st.markdown("#### 대응 권고")

                    for index, item in enumerate(
                        incident_ai.get("response_recommendations", []) or [],
                        start=1
                    ):
                        st.markdown(f"{index}. {item}")

                    st.markdown("#### 분석가 주의사항")
                    st.warning(incident_ai.get("analyst_caution", "-"))

            st.markdown("---")

            section_header(
                "Response Playbook · SOAR-lite"
            )

            st.caption(
                "Incident 유형과 증거에 따라 사전 정의된 대응 절차를 추천합니다. "
                "현재 MVP는 실제 계정 잠금·네트워크 차단을 자동 실행하지 않으며, "
                "관리자 승인과 처리 상태를 기록합니다."
            )

            playbook_ok, playbook_data = load_incident_playbook(
                incident_id
            )

            if not playbook_ok:
                st.error(
                    "Playbook을 불러오지 못했습니다: "
                    + str(
                        playbook_data.get(
                            "detail",
                            "알 수 없는 오류"
                        )
                    )
                )

            else:
                playbook_status = str(
                    playbook_data.get(
                        "status",
                        "PENDING"
                    )
                )

                progress = float(
                    playbook_data.get(
                        "progress_percent",
                        0
                    )
                    or 0
                )

                completed_count = int(
                    playbook_data.get(
                        "completed_step_count",
                        0
                    )
                    or 0
                )

                total_count = int(
                    playbook_data.get(
                        "total_step_count",
                        0
                    )
                    or 0
                )

                st.markdown(
                    f"""
                    <div class="playbook-shell">
                        <div class="playbook-top">
                            <div>
                                <div class="playbook-name">
                                    {playbook_data.get("playbook_name", "-")}
                                </div>
                                <div class="playbook-meta">
                                    Incident #{incident_id} ·
                                    {incident.get("severity", "-")} ·
                                    Human-in-the-loop Response
                                </div>
                            </div>
                            <div class="playbook-status">
                                {playbook_status}
                            </div>
                        </div>
                        <div class="playbook-progress-track">
                            <div class="playbook-progress-fill"
                                 style="width:{max(0, min(progress, 100))}%;">
                            </div>
                        </div>
                        <div class="playbook-meta">
                            진행률 {progress:.1f}% ·
                            {completed_count} / {total_count} 단계 처리
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                playbook_steps = (
                    playbook_data.get("steps", [])
                    or []
                )

                for step in playbook_steps:
                    step_id = str(
                        step.get("step_id", "-")
                    )
                    step_status = str(
                        step.get("status", "PENDING")
                    )
                    approval_required = bool(
                        step.get(
                            "approval_required",
                            False
                        )
                    )

                    st.markdown(
                        f"""
                        <div class="playbook-step-card">
                            <div class="playbook-step-title">
                                {step_id} · {step.get("title", "-")}
                            </div>
                            <div class="playbook-step-desc">
                                {step.get("description", "-")}
                            </div>
                            <span class="playbook-step-badge">
                                {step_status}
                            </span>
                            <span class="playbook-step-badge">
                                {"관리자 승인 필요" if approval_required else "조사/처리 단계"}
                            </span>
                            <span class="playbook-step-badge">
                                실제 시스템 자동 실행 없음
                            </span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

                    button_left, button_right, _ = st.columns(
                        [1, 1, 4]
                    )

                    if approval_required:
                        with button_left:
                            approve_disabled = (
                                step_status
                                in {
                                    "APPROVED",
                                    "COMPLETED",
                                    "SKIPPED"
                                }
                            )

                            if st.button(
                                "승인",
                                key=(
                                    f"pb_approve_"
                                    f"{incident_id}_"
                                    f"{step_id}"
                                ),
                                disabled=approve_disabled,
                                use_container_width=True
                            ):
                                ok, result = (
                                    update_incident_playbook_step(
                                        incident_id,
                                        step_id,
                                        "APPROVE"
                                    )
                                )

                                if ok:
                                    st.rerun()
                                else:
                                    st.error(
                                        result.get(
                                            "detail",
                                            "승인 실패"
                                        )
                                    )

                    with button_right:
                        complete_disabled = (
                            step_status
                            in {
                                "COMPLETED",
                                "SKIPPED"
                            }
                            or (
                                approval_required
                                and step_status
                                != "APPROVED"
                            )
                        )

                        if st.button(
                            "처리 완료",
                            key=(
                                f"pb_complete_"
                                f"{incident_id}_"
                                f"{step_id}"
                            ),
                            disabled=complete_disabled,
                            use_container_width=True
                        ):
                            ok, result = (
                                update_incident_playbook_step(
                                    incident_id,
                                    step_id,
                                    "COMPLETE"
                                )
                            )

                            if ok:
                                st.rerun()
                            else:
                                st.error(
                                    result.get(
                                        "detail",
                                        "처리 실패"
                                    )
                                )

                history = (
                    playbook_data.get("history", [])
                    or []
                )

                if history:
                    st.markdown("#### 대응 이력")

                    for item in reversed(history[-10:]):
                        action_name = {
                            "PLAYBOOK_CREATED": "Playbook 생성",
                            "STEP_APPROVED": "관리자 승인",
                            "STEP_COMPLETED": "처리 완료",
                            "STEP_SKIPPED": "단계 건너뜀"
                        }.get(
                            item.get("action"),
                            item.get("action", "-")
                        )

                        step_title = (
                            item.get("step_title")
                            or "Incident"
                        )

                        st.markdown(
                            f"""
                            <div class="playbook-history">
                                {item.get("timestamp", "-")} ·
                                <b>{action_name}</b> ·
                                {step_title}
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

            st.markdown("---")

            section_header(
                "연관 보안 이벤트"
            )

            related_df = pd.DataFrame()

            if related_event_ids and "id" in df.columns:
                normalized_ids = {
                    str(value)
                    for value in related_event_ids
                }

                related_df = df[
                    df["id"]
                    .astype(str)
                    .isin(normalized_ids)
                ].copy()

            elif storyline and "id" in df.columns:
                storyline_ids = {
                    str(step.get("event_id"))
                    for step in storyline
                    if step.get("event_id") is not None
                }

                related_df = df[
                    df["id"]
                    .astype(str)
                    .isin(storyline_ids)
                ].copy()

            if not related_df.empty:
                related_df = related_df.sort_values(
                    "timestamp",
                    ascending=True
                )

                render_timeline(
                    related_df,
                    height=300
                )

            else:
                st.info(
                    "연관 이벤트 상세 데이터를 현재 이벤트 목록에서 찾지 못했습니다."
                )

            # -------------------------------------------------
            # 선택 이벤트 상세 / AI 분석 연결
            # -------------------------------------------------

            selected_event_id = None
            selected = None

            candidate_ids = []

            for step in reversed(storyline):
                step_event_id = step.get(
                    "event_id"
                )

                if step_event_id is not None:
                    candidate_ids.append(
                        step_event_id
                    )

            for event_id in reversed(
                related_event_ids
            ):
                candidate_ids.append(
                    event_id
                )

            if candidate_ids and "id" in df.columns:

                event_options = {}

                for event_id in candidate_ids:
                    matched = df[
                        df["id"].astype(str)
                        == str(event_id)
                    ]

                    if matched.empty:
                        continue

                    row = matched.iloc[0]

                    label = (
                        f"#{row.get('id', '-')}  |  "
                        f"{row.get('risk_level', '-')}  |  "
                        f"{event_type_korean(row.get('event_type', '-'))}  |  "
                        f"Risk {row.get('risk_score', '-')}"
                    )

                    event_options[
                        label
                    ] = row

                if event_options:

                    section_header(
                        "연관 이벤트 상세 분석"
                    )

                    selected_event_label = st.selectbox(
                        "상세 분석할 연관 이벤트를 선택하세요.",
                        list(
                            event_options.keys()
                        ),
                        key="incident_related_event_select"
                    )

                    selected = event_options[
                        selected_event_label
                    ]

                    selected_event_id = int(
                        selected["id"]
                    )

                    risk_level = str(
                        selected.get(
                            "risk_level",
                            "-"
                        )
                    )

                    risk_score = display_value(
                        selected.get(
                            "risk_score"
                        )
                    )

                    detail1, detail2, detail3, detail4 = st.columns(4)

                    with detail1:
                        detail_card(
                            "사용자",
                            selected.get("user")
                        )
                        detail_card(
                            "이벤트 유형",
                            event_type_korean(
                                selected.get("event_type")
                            )
                        )

                    with detail2:
                        detail_card(
                            "Source IP",
                            selected.get("source_ip")
                        )
                        detail_card(
                            "실행 프로세스",
                            selected.get("process_name")
                        )

                    with detail3:
                        detail_card(
                            "접근 파일",
                            selected.get("file_name")
                        )
                        detail_card(
                            "파일 등급",
                            selected.get("file_grade")
                        )

                    with detail4:
                        detail_card(
                            "로그인 실패 횟수",
                            selected.get("login_fail_count")
                        )
                        detail_card(
                            "파일 접근 횟수",
                            selected.get("file_access_count")
                        )

                    section_header(
                        "탐지 근거"
                    )

                    reason_text = selected.get(
                        "reasons"
                    )

                    reasons = []

                    if (
                        reason_text
                        and pd.notna(reason_text)
                    ):
                        reasons = [
                            reason.strip()
                            for reason
                            in str(reason_text).split(",")
                            if reason.strip()
                        ]

                    if reasons:
                        for index, reason in enumerate(
                            reasons,
                            start=1
                        ):
                            st.markdown(
                                (
                                    '<div class="evidence-item">'
                                    f'<div class="evidence-number">{index:02d}</div>'
                                    f'<div>{safe_html(reason)}</div>'
                                    '</div>'
                                ),
                                unsafe_allow_html=True
                            )
                    else:
                        st.info(
                            "현재 이벤트에 기록된 탐지 근거가 없습니다."
                        )

                    # -------------------------------------------------
                    # Explainable Risk Score / 점수 영수증
                    # -------------------------------------------------

                    section_header(
                        "Explainable Risk Score · 점수 영수증"
                    )

                    explain_success, risk_explanation = (
                        load_risk_explanation(selected_event_id)
                    )

                    if explain_success:
                        plain_summary = risk_explanation.get(
                            "plain_summary"
                        )
                        decision_text = risk_explanation.get(
                            "decision_text"
                        )

                        if plain_summary:
                            st.info(plain_summary)

                        if risk_explanation.get("historical_fallback", False):
                            st.caption(
                                risk_explanation.get(
                                    "note",
                                    "과거 이벤트의 상세 구성 점수는 저장되어 있지 않습니다."
                                )
                            )

                            hist1, hist2 = st.columns(2)
                            with hist1:
                                st.metric(
                                    "최종 Event Risk",
                                    f"{float(risk_explanation.get('final_score', 0) or 0):.2f}"
                                )
                            with hist2:
                                st.metric(
                                    "위험 등급",
                                    risk_explanation.get("risk_level", "-")
                                )

                            if decision_text:
                                st.write("**관리자 판단**")
                                st.write(decision_text)

                        else:
                            st.caption(
                                "최종 점수가 어떤 탐지 계층의 기여로 만들어졌는지 "
                                "이벤트 발생 당시 계산값을 일반인도 이해할 수 있도록 풀어 표시합니다."
                            )

                            components = (
                                risk_explanation.get("components", [])
                                or []
                            )

                            component_columns = (
                                st.columns(len(components))
                                if components
                                else []
                            )

                            for component, column in zip(
                                components,
                                component_columns
                            ):
                                contribution = float(
                                    component.get("contribution", 0)
                                    or 0
                                )
                                sign = "+" if contribution > 0 else ""

                                with column:
                                    st.metric(
                                        component.get(
                                            "label",
                                            "탐지 계층"
                                        ),
                                        f"{sign}{contribution:.2f}",
                                        help=(
                                            component.get(
                                                "plain_explanation"
                                            )
                                            or component.get(
                                                "description"
                                            )
                                        )
                                    )

                            st.write("**점수 영수증**")
                            score_receipt = (
                                risk_explanation.get(
                                    "score_receipt",
                                    []
                                )
                                or []
                            )

                            if score_receipt:
                                for line in score_receipt:
                                    st.markdown(
                                        f"- {line}"
                                    )
                            else:
                                st.caption(
                                    "저장된 점수 영수증 정보가 없습니다."
                                )

                            st.write("**왜 이 점수가 나왔나**")
                            for component in components:
                                st.markdown(
                                    "- **"
                                    + str(
                                        component.get(
                                            "label",
                                            "탐지 계층"
                                        )
                                    )
                                    + "** · "
                                    + str(
                                        component.get(
                                            "plain_explanation"
                                        )
                                        or component.get(
                                            "description",
                                            "설명 없음"
                                        )
                                    )
                                )

                            score_before_floor = float(
                                risk_explanation.get(
                                    "score_before_floor",
                                    0
                                )
                                or 0
                            )
                            final_explain_score = float(
                                risk_explanation.get(
                                    "final_score",
                                    0
                                )
                                or 0
                            )

                            score1, score2, score3 = st.columns(3)
                            with score1:
                                st.metric(
                                    "안전장치 적용 전",
                                    f"{score_before_floor:.2f}"
                                )
                            with score2:
                                st.metric(
                                    "최종 Event Risk",
                                    f"{final_explain_score:.2f}"
                                )
                            with score3:
                                st.metric(
                                    "최종 위험 등급",
                                    risk_explanation.get(
                                        "risk_level",
                                        "-"
                                    )
                                )

                            if risk_explanation.get(
                                "floor_applied",
                                False
                            ):
                                st.warning(
                                    "위험도 최소 보장 안전장치 적용 · "
                                    + str(
                                        risk_explanation.get(
                                            "floor_reason",
                                            "고위험 탐지 신호에 따른 최소 위험도 적용"
                                        )
                                    )
                                )
                            else:
                                st.caption(
                                    "Sequence/Baseline 최소 위험도 안전장치의 추가 상향은 없었습니다."
                                )

                            if decision_text:
                                st.write("**관리자 판단**")
                                st.write(decision_text)

                            threshold_guide = (
                                risk_explanation.get(
                                    "threshold_guide",
                                    {}
                                )
                                or {}
                            )
                            if threshold_guide:
                                st.caption(
                                    "위험 등급 기준 · "
                                    + " / ".join(
                                        str(value)
                                        for value
                                        in threshold_guide.values()
                                    )
                                )

                            calculation_explanation = (
                                risk_explanation.get(
                                    "calculation_explanation"
                                )
                            )
                            if calculation_explanation:
                                with st.expander(
                                    "위험점수가 필요한 이유"
                                ):
                                    st.write(
                                        calculation_explanation
                                    )

                            st.caption(
                                risk_explanation.get(
                                    "note",
                                    "Dynamic User Risk와 Incident Score는 Event Risk와 별도입니다."
                                )
                            )
                    else:
                        st.warning(
                            "Explainable Risk Score 정보를 불러오지 못했습니다."
                        )


                    section_header(
                        "규칙 기반 대응 권고"
                    )

                    if incident_severity == "CRITICAL":
                        st.error(
                            "상관분석 결과 다단계 고위험 사고로 판단되었습니다. "
                            "사용자 세션·인증 기록·민감정보 접근·USB 및 "
                            "외부 전송 가능 프로세스를 우선 조사하십시오."
                        )
                    elif incident_severity == "HIGH":
                        st.warning(
                            "복수의 위험 행동이 하나의 사고로 연결되었습니다. "
                            "연관 이벤트의 시간 순서와 사용자 행위를 우선 확인하십시오."
                        )
                    else:
                        st.info(
                            "연관 이벤트의 추가 발생 여부와 사용자 행동 변화를 "
                            "지속적으로 확인하십시오."
                        )

                    section_header(
                        "AI 보안 사고 분석"
                    )

                    st.caption(
                        "LLM은 선택한 연관 이벤트의 기존 탐지 결과를 해석하는 "
                        "보조 분석 계층이며 Risk Score나 Incident Correlation "
                        "결과를 변경하지 않습니다."
                    )

                    ai_button_col, ai_info_col = st.columns(
                        [1, 3]
                    )

                    with ai_button_col:
                        run_ai = st.button(
                            "선택 이벤트 AI 분석",
                            use_container_width=True,
                            type="primary"
                        )

                    with ai_info_col:
                        st.caption(
                            f"Incident {incident_id} · "
                            f"Event #{selected_event_id} · "
                            f"{risk_level} · Risk {risk_score}"
                        )

                    if run_ai:
                        with st.spinner(
                            "탐지 근거를 기반으로 AI가 보안 이벤트를 분석하고 있습니다..."
                        ):
                            success, result = run_ai_analysis(
                                selected_event_id
                            )

                        if success:
                            st.session_state[
                                "ai_results"
                            ][
                                selected_event_id
                            ] = result
                        else:
                            st.error(
                                "AI 보안 분석 요청에 실패했습니다."
                            )
                            st.code(
                                result.get(
                                    "detail",
                                    "알 수 없는 오류"
                                )
                            )

                    result = st.session_state[
                        "ai_results"
                    ].get(
                        selected_event_id
                    )

                    if result:
                        ai_result = result.get(
                            "ai_analysis",
                            {}
                        )

                        summary = ai_result.get(
                            "summary",
                            "분석 결과가 없습니다."
                        )

                        scenario = ai_result.get(
                            "threat_scenario",
                            "분석 결과가 없습니다."
                        )

                        evidence = ai_result.get(
                            "evidence",
                            []
                        )

                        recommendations = ai_result.get(
                            "recommendations",
                            []
                        )

                        st.markdown(
                            (
                                '<div class="ai-shell">'
                                '<div class="ai-head">'
                                '<div class="ai-title">AI 보안 사고 분석 보고서</div>'
                                '<div class="ai-model">LLM 보조 분석</div>'
                                '</div>'
                                '<div class="ai-section-label">사고 요약</div>'
                                f'<div class="ai-text">{safe_html(summary)}</div>'
                                '<div class="ai-section-label">의심 위협 시나리오</div>'
                                f'<div class="ai-text">{safe_html(scenario)}</div>'
                                '</div>'
                            ),
                            unsafe_allow_html=True
                        )

                        if evidence:
                            st.markdown(
                                '<div class="ai-section-label">판단 근거</div>',
                                unsafe_allow_html=True
                            )

                            for index, item in enumerate(
                                evidence,
                                start=1
                            ):
                                st.markdown(
                                    (
                                        '<div class="evidence-item">'
                                        f'<div class="evidence-number">AI-{index:02d}</div>'
                                        f'<div>{safe_html(item)}</div>'
                                        '</div>'
                                    ),
                                    unsafe_allow_html=True
                                )

                        if recommendations:
                            st.markdown(
                                '<div class="ai-section-label">대응 권고</div>',
                                unsafe_allow_html=True
                            )

                            for index, item in enumerate(
                                recommendations,
                                start=1
                            ):
                                st.markdown(
                                    (
                                        '<div class="recommendation">'
                                        f'<strong>{index:02d}</strong>'
                                        ' &nbsp;&nbsp; '
                                        f'{safe_html(item)}'
                                        '</div>'
                                    ),
                                    unsafe_allow_html=True
                                )

        else:
            st.warning(
                "현재 필터 조건에 해당하는 보안 사고가 없습니다."
            )

    else:
        st.warning(
            "Incident Correlation 결과가 없습니다. "
            "왼쪽의 공격 시나리오를 실행한 뒤 새로고침하십시오."
        )

        section_header(
            "개별 이벤트 분석"
        )

        st.caption(
            "Incident가 생성되기 전에는 이벤트 모니터링 페이지에서 "
            "개별 Event Risk와 탐지 근거를 확인할 수 있습니다."
        )


# =========================================================
# PAGE 4
# 사용자 행동 분석
# =========================================================

elif page == "사용자 행동 분석":


    # -----------------------------------------------------
    # 모니터링 사용자 관리
    # -----------------------------------------------------

    section_header(
        "모니터링 사용자 관리"
    )

    users_ok, monitored_users = (
        load_monitored_users()
    )

    if not users_ok:
        st.error(
            "모니터링 사용자 목록을 불러오지 못했습니다."
        )
        monitored_users = []

    total_monitored = len(
        monitored_users
    )

    enabled_monitored = sum(
        1
        for item in monitored_users
        if bool(
            item.get(
                "monitoring_enabled",
                False
            )
        )
    )

    learning_monitored = sum(
        1
        for item in monitored_users
        if str(
            item.get(
                "learning_status",
                ""
            )
        ).upper() == "LEARNING"
    )

    admin1, admin2, admin3 = st.columns(3)

    admin_cards = [
        (
            admin1,
            "등록 사용자",
            total_monitored,
            "관리자가 등록한 모니터링 계정"
        ),
        (
            admin2,
            "활성 모니터링",
            enabled_monitored,
            "현재 이벤트 수집 허용 계정"
        ),
        (
            admin3,
            "기준선 학습 중",
            learning_monitored,
            "Adaptive Baseline LEARNING"
        )
    ]

    for (
        column,
        label,
        value,
        foot
    ) in admin_cards:
        with column:
            st.markdown(
                (
                    '<div class="kpi-card">'
                    f'<div class="kpi-label">{safe_html(label)}</div>'
                    f'<div class="kpi-value">{value:,}</div>'
                    f'<div class="kpi-foot">{safe_html(foot)}</div>'
                    '</div>'
                ),
                unsafe_allow_html=True
            )

    with st.expander(
        "＋ 모니터링 사용자 등록",
        expanded=False
    ):
        with st.form(
            "monitored_user_create_form",
            clear_on_submit=True
        ):
            create1, create2 = st.columns(2)

            with create1:
                new_username = st.text_input(
                    "사용자명 *",
                    placeholder="예: 김재경"
                )

                new_display_name = st.text_input(
                    "표시 이름",
                    placeholder="예: 김재경"
                )

            with create2:
                new_department = st.text_input(
                    "부서",
                    placeholder="예: IT"
                )

                new_role = st.text_input(
                    "역할",
                    placeholder="예: Developer"
                )

            create_submitted = st.form_submit_button(
                "모니터링 사용자 등록",
                use_container_width=True
            )

        if create_submitted:
            if not new_username.strip():
                st.error(
                    "사용자명은 반드시 입력해야 합니다."
                )
            else:
                success, result = create_monitored_user(
                    new_username,
                    new_display_name,
                    new_department,
                    new_role
                )

                if success:
                    st.success(
                        f"{new_username.strip()} 사용자를 "
                        "모니터링 대상으로 등록했습니다. "
                        "개인 행동 기준선 학습이 시작됩니다."
                    )
                    st.rerun()
                else:
                    st.error(
                        result.get(
                            "detail",
                            "사용자 등록에 실패했습니다."
                        )
                    )

    if monitored_users:
        st.caption(
            "비활성화하면 새 /events 수집을 차단합니다. "
            "삭제해도 기존 SecurityEvent 감사 이력은 보존됩니다."
        )

        for index, item in enumerate(
            monitored_users
        ):
            username = str(
                item.get(
                    "username",
                    "-"
                )
            )

            display_name = (
                item.get("display_name")
                or username
            )

            department = (
                item.get("department")
                or "-"
            )

            role = (
                item.get("role")
                or "-"
            )

            enabled = bool(
                item.get(
                    "monitoring_enabled",
                    False
                )
            )

            learning_status = str(
                item.get(
                    "learning_status",
                    "LEARNING"
                )
            ).upper()

            learning_count = int(
                item.get(
                    "learning_event_count",
                    0
                )
                or 0
            )

            confidence_weight = float(
                item.get(
                    "confidence_weight",
                    0
                )
                or 0
            )

            row1, row2, row3 = st.columns(
                [5.4, 1.3, 1.3]
            )

            with row1:
                status_text = (
                    "활성"
                    if enabled
                    else "비활성"
                )

                st.markdown(
                    (
                        '<div class="baseline-summary">'
                        '<div class="baseline-top">'
                        '<div>'
                        f'<div class="baseline-user">{safe_html(display_name)}</div>'
                        '<div class="baseline-meta">'
                        f'계정 {safe_html(username)}'
                        ' · '
                        f'{safe_html(department)}'
                        ' · '
                        f'{safe_html(role)}'
                        ' · '
                        f'정상 학습 {learning_count:,}개'
                        ' · '
                        f'가중치 {confidence_weight:.2f}'
                        '</div>'
                        '</div>'
                        f'<div class="baseline-badge">'
                        f'{safe_html(learning_status)} · {safe_html(status_text)}'
                        '</div>'
                        '</div>'
                        '</div>'
                    ),
                    unsafe_allow_html=True
                )

            with row2:
                if enabled:
                    if st.button(
                        "비활성화",
                        key=f"disable_user_{index}_{username}",
                        use_container_width=True
                    ):
                        success, result = (
                            set_monitored_user_enabled(
                                username,
                                False
                            )
                        )

                        if success:
                            st.success(
                                f"{username} 모니터링을 "
                                "비활성화했습니다."
                            )
                            st.rerun()
                        else:
                            st.error(
                                result.get(
                                    "detail",
                                    "비활성화 실패"
                                )
                            )
                else:
                    if st.button(
                        "활성화",
                        key=f"enable_user_{index}_{username}",
                        use_container_width=True
                    ):
                        success, result = (
                            set_monitored_user_enabled(
                                username,
                                True
                            )
                        )

                        if success:
                            st.success(
                                f"{username} 모니터링을 "
                                "활성화했습니다."
                            )
                            st.rerun()
                        else:
                            st.error(
                                result.get(
                                    "detail",
                                    "활성화 실패"
                                )
                            )

            with row3:
                delete_confirm = st.checkbox(
                    "삭제 확인",
                    key=f"delete_confirm_{index}_{username}"
                )

                if st.button(
                    "삭제",
                    key=f"delete_user_{index}_{username}",
                    use_container_width=True,
                    disabled=not delete_confirm
                ):
                    success, result = (
                        delete_monitored_user(
                            username
                        )
                    )

                    if success:
                        st.success(
                            f"{username} 등록을 삭제했습니다. "
                            "기존 보안 이벤트는 보존됩니다."
                        )
                        st.rerun()
                    else:
                        st.error(
                            result.get(
                                "detail",
                                "사용자 삭제 실패"
                            )
                        )
    else:
        st.info(
            "등록된 모니터링 사용자가 없습니다. "
            "위 등록 메뉴에서 사용자를 추가하세요."
        )


    section_header(
        "Adaptive Personal UEBA"
    )

    users_success, monitored_users = (
        load_monitored_users()
    )

    if not users_success:
        st.error(
            "모니터링 사용자 정보를 불러오지 못했습니다. "
            "FastAPI /users 연결 상태를 확인하세요."
        )
        st.stop()

    if not monitored_users:
        st.info(
            "등록된 모니터링 사용자가 없습니다. "
            "먼저 관리 대상 사용자를 등록하세요."
        )
        st.stop()

    enabled_users = [
        item
        for item in monitored_users
        if item.get("monitoring_enabled", False)
    ]

    selectable_users = (
        enabled_users
        if enabled_users
        else monitored_users
    )

    user_map = {
        str(item.get("username")): item
        for item in selectable_users
        if item.get("username")
    }

    selected_user = st.selectbox(
        "분석할 모니터링 사용자를 선택하세요.",
        list(user_map.keys()),
        key="ueba_user_select"
    )

    selected_registration = user_map[
        selected_user
    ]

    profile_success, behavior_profile = (
        load_user_behavior_profile(
            selected_user
        )
    )

    if not profile_success:
        st.error(
            "선택 사용자의 개인 행동 기준선을 "
            "불러오지 못했습니다."
        )
        st.stop()

    user_df = df[
        df["user"].astype(str)
        == selected_user
    ].copy()

    display_name = (
        selected_registration.get("display_name")
        or selected_user
    )

    department = (
        selected_registration.get("department")
        or "-"
    )

    role = (
        selected_registration.get("role")
        or "-"
    )

    monitoring_text = (
        "모니터링 활성"
        if selected_registration.get(
            "monitoring_enabled",
            False
        )
        else "모니터링 중지"
    )

    confidence_level = str(
        behavior_profile.get(
            "confidence_level",
            selected_registration.get(
                "learning_status",
                "LEARNING"
            )
        )
    )

    learning_event_count = int(
        behavior_profile.get(
            "learning_event_count",
            behavior_profile.get(
                "event_count",
                selected_registration.get(
                    "learning_event_count",
                    0
                )
            )
        )
        or 0
    )

    confidence_weight = float(
        behavior_profile.get(
            "confidence_weight",
            selected_registration.get(
                "confidence_weight",
                0
            )
        )
        or 0
    )

    confidence_percent = max(
        0,
        min(
            confidence_weight * 100,
            100
        )
    )

    profile_html = (
        '<div class="baseline-summary">'
        '<div class="baseline-top">'
        '<div>'
        f'<div class="baseline-user">{safe_html(display_name)}</div>'
        '<div class="baseline-meta">'
        f'계정 {safe_html(selected_user)}'
        ' &nbsp;·&nbsp; '
        f'{safe_html(department)}'
        ' &nbsp;·&nbsp; '
        f'{safe_html(role)}'
        ' &nbsp;·&nbsp; '
        f'{safe_html(monitoring_text)}'
        '</div>'
        '</div>'
        f'<div class="baseline-badge">'
        f'BASELINE {safe_html(confidence_level)}'
        '</div>'
        '</div>'
        '</div>'
    )

    st.markdown(
        profile_html,
        unsafe_allow_html=True
    )


    # -----------------------------------------------------
    # 기준선 학습 상태
    # -----------------------------------------------------

    section_header(
        "개인 행동 기준선 학습 상태"
    )

    b1, b2, b3, b4 = st.columns(4)

    baseline_status_cards = [
        (
            b1,
            "학습 상태",
            confidence_level,
            "개인 기준선 신뢰도"
        ),
        (
            b2,
            "정상 학습 이벤트",
            f"{learning_event_count:,}",
            "LOW 이벤트만 기준선 학습"
        ),
        (
            b3,
            "기준선 가중치",
            f"{confidence_weight:.2f}",
            "학습량에 따른 탐지 반영도"
        ),
        (
            b4,
            "현재 수집 이벤트",
            f"{len(user_df):,}",
            "선택 사용자의 전체 이벤트"
        )
    ]

    for (
        column,
        label,
        value,
        foot
    ) in baseline_status_cards:

        with column:
            html = (
                '<div class="kpi-card">'
                f'<div class="kpi-label">{safe_html(label)}</div>'
                f'<div class="kpi-value">{safe_html(value)}</div>'
                f'<div class="kpi-foot">{safe_html(foot)}</div>'
                '</div>'
            )

            st.markdown(
                html,
                unsafe_allow_html=True
            )

    st.markdown(
        (
            '<div class="learning-note">'
            '<strong>Learning Guard</strong> · '
            '현재 개인 행동 기준선은 이전 이벤트 중 '
            '<strong>LOW 위험 등급</strong>으로 판정된 정상 행동만 '
            '학습합니다. MEDIUM / HIGH / CRITICAL 이벤트는 '
            '감사 및 탐지 기록에는 유지되지만 정상 행동 기준에는 '
            '포함되지 않습니다.'
            '<div class="confidence-track">'
            f'<div class="confidence-fill" '
            f'style="width:{confidence_percent:.1f}%"></div>'
            '</div>'
            '</div>'
        ),
        unsafe_allow_html=True
    )


    # -----------------------------------------------------
    # 학습된 정상 행동 프로필
    # -----------------------------------------------------

    section_header(
        "학습된 정상 행동 프로필"
    )

    active_hours = behavior_profile.get(
        "active_hours",
        []
    )

    active_weekdays = behavior_profile.get(
        "active_weekdays",
        []
    )

    known_ips = behavior_profile.get(
        "known_ips",
        []
    )

    normal_processes = behavior_profile.get(
        "normal_processes",
        []
    )

    average_file_access = behavior_profile.get(
        "average_file_access",
        behavior_profile.get(
            "avg_file_access",
            0
        )
    )

    usb_usage_rate = behavior_profile.get(
        "usb_usage_rate",
        0
    )

    weekday_names = {
        0: "월",
        1: "화",
        2: "수",
        3: "목",
        4: "금",
        5: "토",
        6: "일"
    }

    if isinstance(active_hours, list):
        active_hours_text = (
            ", ".join(
                f"{int(hour):02d}시"
                for hour in active_hours
            )
            if active_hours
            else "학습 데이터 부족"
        )
    else:
        active_hours_text = str(
            active_hours or "학습 데이터 부족"
        )

    if isinstance(active_weekdays, list):
        weekday_parts = []

        for day in active_weekdays:
            try:
                day_number = int(day)
                weekday_parts.append(
                    weekday_names.get(
                        day_number,
                        str(day)
                    )
                )
            except (TypeError, ValueError):
                weekday_parts.append(
                    str(day)
                )

        active_weekdays_text = (
            ", ".join(weekday_parts)
            if weekday_parts
            else "학습 데이터 부족"
        )
    else:
        active_weekdays_text = str(
            active_weekdays
            or "학습 데이터 부족"
        )

    if isinstance(known_ips, list):
        known_ips_text = (
            ", ".join(
                str(value)
                for value in known_ips
            )
            if known_ips
            else "학습 데이터 부족"
        )
    else:
        known_ips_text = str(
            known_ips or "학습 데이터 부족"
        )

    if isinstance(normal_processes, list):
        normal_processes_text = (
            ", ".join(
                str(value)
                for value in normal_processes
            )
            if normal_processes
            else "학습 데이터 부족"
        )
    else:
        normal_processes_text = str(
            normal_processes
            or "학습 데이터 부족"
        )

    try:
        average_file_access_text = (
            f"{float(average_file_access):.1f}회"
        )
    except (TypeError, ValueError):
        average_file_access_text = "-"

    try:
        usb_rate_number = float(
            usb_usage_rate
        )

        if usb_rate_number <= 1:
            usb_rate_number *= 100

        usb_usage_text = (
            f"{usb_rate_number:.1f}%"
        )
    except (TypeError, ValueError):
        usb_usage_text = "-"

    p1, p2, p3 = st.columns(3)

    profile_cards_first = [
        (
            p1,
            "평소 활동 시간",
            active_hours_text,
            "개인별 시간대 패턴"
        ),
        (
            p2,
            "평소 활동 요일",
            active_weekdays_text,
            "개인별 요일 패턴"
        ),
        (
            p3,
            "알려진 Source IP",
            known_ips_text,
            "반복 관찰된 정상 접속지"
        )
    ]

    for (
        column,
        label,
        value,
        foot
    ) in profile_cards_first:

        with column:
            st.markdown(
                (
                    '<div class="baseline-card">'
                    f'<div class="baseline-card-label">{safe_html(label)}</div>'
                    f'<div class="baseline-card-value">{safe_html(value)}</div>'
                    f'<div class="baseline-card-foot">{safe_html(foot)}</div>'
                    '</div>'
                ),
                unsafe_allow_html=True
            )

    st.write("")

    p4, p5, p6 = st.columns(3)

    profile_cards_second = [
        (
            p4,
            "정상 프로세스",
            normal_processes_text,
            "반복 실행된 개인별 정상 프로세스"
        ),
        (
            p5,
            "평균 파일 접근량",
            average_file_access_text,
            "정상 행동의 평균 파일 접근"
        ),
        (
            p6,
            "USB 사용률",
            usb_usage_text,
            "정상 학습 이벤트 기준"
        )
    ]

    for (
        column,
        label,
        value,
        foot
    ) in profile_cards_second:

        with column:
            st.markdown(
                (
                    '<div class="baseline-card">'
                    f'<div class="baseline-card-label">{safe_html(label)}</div>'
                    f'<div class="baseline-card-value">{safe_html(value)}</div>'
                    f'<div class="baseline-card-foot">{safe_html(foot)}</div>'
                    '</div>'
                ),
                unsafe_allow_html=True
            )


    # -----------------------------------------------------
    # Dynamic User Risk
    # -----------------------------------------------------

    section_header(
        "Dynamic User Risk"
    )

    dynamic_success, dynamic_risk = (
        load_dynamic_user_risk(
            selected_user
        )
    )

    if dynamic_success:
        dynamic_score = float(
            dynamic_risk.get(
                "dynamic_risk_score",
                0
            )
            or 0
        )

        dynamic_level = str(
            dynamic_risk.get(
                "dynamic_risk_level",
                "LOW"
            )
        ).upper()

        dynamic_width = max(
            0,
            min(
                dynamic_score,
                100
            )
        )

        risk_event_count = int(
            dynamic_risk.get(
                "risk_event_count",
                0
            )
            or 0
        )

        cluster_count = int(
            dynamic_risk.get(
                "cluster_count",
                0
            )
            or 0
        )

        contributing_count = int(
            dynamic_risk.get(
                "contributing_cluster_count",
                0
            )
            or 0
        )

        window_hours = int(
            dynamic_risk.get(
                "window_hours",
                24
            )
            or 24
        )

        half_life_hours = float(
            dynamic_risk.get(
                "half_life_hours",
                6
            )
            or 6
        )

        cluster_minutes = int(
            dynamic_risk.get(
                "cluster_minutes",
                10
            )
            or 10
        )

        badge_class = dynamic_badge_class(
            dynamic_level
        )

        st.markdown(
            (
                '<div class="dynamic-risk-shell">'
                '<div class="dynamic-risk-top">'
                '<div>'
                '<div class="dynamic-risk-label">CURRENT USER STATE</div>'
                f'<div class="dynamic-risk-score">{dynamic_score:.2f}</div>'
                '<div class="dynamic-risk-meta">'
                f'최근 {window_hours}시간 · '
                f'{cluster_minutes}분 행동 군집 · '
                f'{half_life_hours:g}시간 반감기'
                '</div>'
                '</div>'
                f'<div class="dynamic-risk-badge {badge_class}">'
                f'{safe_html(dynamic_level)}'
                '</div>'
                '</div>'
                '<div class="dynamic-track">'
                f'<div class="dynamic-fill" style="width:{dynamic_width:.2f}%"></div>'
                '</div>'
                '</div>'
            ),
            unsafe_allow_html=True
        )

        d1, d2, d3, d4 = st.columns(4)

        dynamic_cards = [
            (
                d1,
                "현재 User Risk",
                f"{dynamic_score:.2f}",
                "개별 Event Risk와 분리된 사용자 상태"
            ),
            (
                d2,
                "사용자 상태",
                dynamic_level,
                "최근 위험 행동을 종합한 등급"
            ),
            (
                d3,
                "위험 행동 군집",
                f"{cluster_count:,}",
                f"MEDIUM 이상 {risk_event_count:,}개를 군집화"
            ),
            (
                d4,
                "실제 기여 군집",
                f"{contributing_count:,}",
                "체감 가중치·시간 감쇠 후 반영"
            )
        ]

        for (
            column,
            label,
            value,
            foot
        ) in dynamic_cards:
            with column:
                st.markdown(
                    (
                        '<div class="kpi-card">'
                        f'<div class="kpi-label">{safe_html(label)}</div>'
                        f'<div class="kpi-value">{safe_html(value)}</div>'
                        f'<div class="kpi-foot">{safe_html(foot)}</div>'
                        '</div>'
                    ),
                    unsafe_allow_html=True
                )

        st.markdown(
            (
                '<div class="learning-note">'
                '<strong>Dynamic Risk 정책</strong> · '
                'LOW 정상 이벤트는 사용자 위험 누적에서 제외하고, '
                'MEDIUM 이상 이벤트만 행동 유형별 군집으로 압축합니다. '
                '같은 행동의 반복은 체감 가중치를 적용하며 시간이 지나면 '
                '위험 기여도가 감소합니다. Dynamic User Risk는 개별 '
                'Event Risk에 다시 더하지 않아 자기증폭을 방지합니다.'
                '</div>'
            ),
            unsafe_allow_html=True
        )

        contributors = (
            dynamic_risk.get(
                "contributors",
                []
            )
            or []
        )

        section_header(
            "Dynamic Risk 주요 기여 행동"
        )

        if contributors:
            contributor_rows = []

            for contributor in contributors:
                contributor_rows.append(
                    {
                        "시간": format_timestamp(
                            contributor.get(
                                "timestamp"
                            )
                        ),
                        "행동 유형": event_type_korean(
                            contributor.get(
                                "event_type",
                                "-"
                            )
                        ),
                        "대표 Event Risk": contributor.get(
                            "risk_score",
                            0
                        ),
                        "Event Level": contributor.get(
                            "risk_level",
                            "-"
                        ),
                        "군집 이벤트": contributor.get(
                            "cluster_event_count",
                            0
                        ),
                        "동일 유형 순번": contributor.get(
                            "same_type_occurrence",
                            1
                        ),
                        "유형 가중치": contributor.get(
                            "type_weight",
                            1
                        ),
                        "시간 감쇠": contributor.get(
                            "decay_weight",
                            1
                        ),
                        "최종 기여도": contributor.get(
                            "weighted_score",
                            0
                        )
                    }
                )

            contributor_df = pd.DataFrame(
                contributor_rows
            )

            left_dynamic, right_dynamic = st.columns(
                [1.25, 1]
            )

            with left_dynamic:
                st.dataframe(
                    contributor_df,
                    use_container_width=True,
                    hide_index=True,
                    height=270
                )

            with right_dynamic:
                contribution_chart = (
                    contributor_df[
                        [
                            "행동 유형",
                            "최종 기여도"
                        ]
                    ]
                    .groupby(
                        "행동 유형"
                    )[
                        "최종 기여도"
                    ]
                    .sum()
                    .sort_values(
                        ascending=False
                    )
                )

                st.markdown(
                    '<div class="panel-title">'
                    '행동 유형별 위험 기여도'
                    '</div>'
                    '<div class="panel-sub">'
                    '현재 Dynamic User Risk를 구성하는 행동 증거'
                    '</div>',
                    unsafe_allow_html=True
                )

                st.bar_chart(
                    contribution_chart,
                    height=230
                )

            contribution_timeline = (
                contributor_df[
                    [
                        "시간",
                        "최종 기여도"
                    ]
                ]
                .copy()
            )

            contribution_timeline[
                "시간"
            ] = pd.to_datetime(
                contribution_timeline[
                    "시간"
                ],
                errors="coerce"
            )

            contribution_timeline = (
                contribution_timeline
                .dropna(
                    subset=[
                        "시간"
                    ]
                )
                .sort_values(
                    "시간"
                )
            )

            if not contribution_timeline.empty:
                section_header(
                    "최근 위험 기여 행동 추이"
                )

                st.caption(
                    "현재 API는 Dynamic User Risk의 과거 스냅샷을 "
                    "별도 저장하지 않으므로, 이 그래프는 실제 User Risk "
                    "점수 이력이 아니라 현재 점수를 구성하는 위험 행동 "
                    "군집의 시간별 기여도를 표시합니다."
                )

                st.line_chart(
                    contribution_timeline
                    .set_index(
                        "시간"
                    )[
                        "최종 기여도"
                    ],
                    height=280
                )
        else:
            st.info(
                "최근 24시간 동안 Dynamic User Risk에 "
                "기여하는 MEDIUM 이상 행동 군집이 없습니다."
            )

        dynamic_reason = dynamic_risk.get(
            "reason"
        )

        if dynamic_reason:
            st.caption(
                f"판정 근거 · {dynamic_reason}"
            )

    else:
        st.warning(
            "Dynamic User Risk 정보를 불러오지 못했습니다. "
            "FastAPI /users/{user}/dynamic-risk 연결 상태를 확인하세요."
        )


    # -----------------------------------------------------
    # 현재 사용자 위험 지표
    # -----------------------------------------------------

    section_header(
        "개별 이벤트 위험 지표"
    )

    event_count = len(
        user_df
    )

    average_risk = (
        user_df["risk_score"].mean()
        if (
            not user_df.empty
            and "risk_score" in user_df.columns
        )
        else 0
    )

    max_risk = (
        user_df["risk_score"].max()
        if (
            not user_df.empty
            and "risk_score" in user_df.columns
        )
        else 0
    )

    high_risk_events = (
        len(
            user_df[
                user_df["risk_level"].isin(
                    [
                        "HIGH",
                        "CRITICAL"
                    ]
                )
            ]
        )
        if (
            not user_df.empty
            and "risk_level" in user_df.columns
        )
        else 0
    )

    r1, r2, r3, r4 = st.columns(4)

    risk_cards = [
        (
            r1,
            "전체 이벤트",
            f"{event_count:,}",
            "수집된 사용자 활동"
        ),
        (
            r2,
            "평균 Risk",
            f"{average_risk:.1f}",
            "사용자 평균 위험 점수"
        ),
        (
            r3,
            "최고 Risk",
            f"{max_risk:.1f}",
            "관찰된 최고 위험도"
        ),
        (
            r4,
            "고위험 이벤트",
            f"{high_risk_events:,}",
            "HIGH + CRITICAL"
        )
    ]

    for (
        column,
        label,
        value,
        foot
    ) in risk_cards:

        with column:
            st.markdown(
                (
                    '<div class="kpi-card">'
                    f'<div class="kpi-label">{safe_html(label)}</div>'
                    f'<div class="kpi-value">{safe_html(value)}</div>'
                    f'<div class="kpi-foot">{safe_html(foot)}</div>'
                    '</div>'
                ),
                unsafe_allow_html=True
            )


    # -----------------------------------------------------
    # 위험도 및 이벤트 구성
    # -----------------------------------------------------

    if not user_df.empty:

        section_header(
            "사용자 위험도 분석"
        )

        user_risk_counts = (
            user_df["risk_level"]
            .value_counts()
            .reindex(
                risk_order,
                fill_value=0
            )
            if "risk_level" in user_df.columns
            else pd.Series(
                [0, 0, 0, 0],
                index=risk_order
            )
        )

        risk_left, risk_right = st.columns(
            [1, 1]
        )

        with risk_left:
            render_severity_panel(
                user_risk_counts
            )

        with risk_right:
            st.markdown(
                '<div class="panel-title">'
                '사용자 이벤트 유형'
                '</div>'
                '<div class="panel-sub">'
                '선택 사용자의 이벤트 유형별 발생 건수'
                '</div>',
                unsafe_allow_html=True
            )

            if "event_type" in user_df.columns:
                event_counts = (
                    user_df["event_type"]
                    .apply(event_type_korean)
                    .value_counts()
                )

                st.bar_chart(
                    event_counts,
                    height=300
                )


        # -------------------------------------------------
        # Risk Score 시간 추이
        # -------------------------------------------------

        section_header(
            "개별 Event Risk 시간 추이"
        )

        st.caption(
            "개별 보안 이벤트의 Risk Score가 시간에 따라 어떻게 변화하는지 "
            "확인합니다. Dynamic User Risk와는 별도의 지표입니다. "
            "시간 순서로 확인합니다."
        )

        if (
            "timestamp" in user_df.columns
            and "risk_score" in user_df.columns
        ):

            risk_timeline = user_df[
                [
                    "timestamp",
                    "risk_score"
                ]
            ].copy()

            risk_timeline = (
                risk_timeline
                .dropna(
                    subset=[
                        "timestamp",
                        "risk_score"
                    ]
                )
                .sort_values(
                    "timestamp",
                    ascending=True
                )
            )

            if not risk_timeline.empty:
                risk_timeline = (
                    risk_timeline
                    .set_index(
                        "timestamp"
                    )
                )

                st.line_chart(
                    risk_timeline[
                        "risk_score"
                    ],
                    height=320
                )
            else:
                st.info(
                    "Risk Score 시간 추이를 "
                    "표시할 데이터가 없습니다."
                )


        # -------------------------------------------------
        # 최근 활동
        # -------------------------------------------------

        section_header(
            "사용자 최근 활동"
        )

        render_timeline(
            user_df,
            height=500
        )

    else:
        section_header(
            "사용자 활동 데이터"
        )

        st.info(
            "이 사용자는 모니터링 대상으로 등록되어 있지만 "
            "아직 수집된 이벤트가 없습니다. "
            "Collector에서 정상 행동이 수집되면 개인 행동 "
            "기준선이 단계적으로 학습됩니다."
        )



    # -------------------------------------------------
    # Adaptive Personal UEBA 비교 시연
    # -------------------------------------------------

    section_header("Adaptive Personal UEBA 비교 시연")

    st.markdown(
        """
        <div class="adaptive-demo-shell">
            <div class="adaptive-demo-head">동일 행동 · 서로 다른 개인 기준선</div>
            <div class="adaptive-demo-sub">
                23:00 PowerShell 실행이라는 동일 행동을 일반 주간 사무직 사용자와
                재택/유연근무 IT 사용자에게 적용하여 개인 기준선과 Adaptive 보정 결과를 비교합니다.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    demo_col1, demo_col2 = st.columns([1, 3])

    with demo_col1:
        if st.button(
            "Adaptive 비교 실행",
            use_container_width=True,
            key="run_adaptive_compare"
        ):
            with st.spinner("개인별 기준선 및 Adaptive 보정 비교 중..."):
                demo_success, demo_result = run_demo_api(
                    "/demo/compare-adaptive-baseline"
                )

            if demo_success:
                st.session_state["adaptive_demo_result"] = demo_result
            else:
                st.error(
                    demo_result.get(
                        "detail",
                        "Adaptive 비교 실행 실패"
                    )
                )

    with demo_col2:
        st.caption(
            "고정 Rule은 두 사용자 모두 23시를 비정상 시간대로 판단하지만, "
            "충분히 학습된 개인 정상 패턴과 일치하는 경우에만 시간 규칙의 기여도를 제한적으로 보정합니다."
        )

    adaptive_result = st.session_state.get("adaptive_demo_result")

    if adaptive_result:
        same_behavior = adaptive_result.get("same_behavior", {})

        st.markdown(
            (
                '<div class="learning-note"><b>동일 테스트 행동</b>&nbsp;&nbsp;'
                f'{safe_html(same_behavior.get("hour", "-"))}:00'
                '&nbsp;&nbsp;/&nbsp;&nbsp;'
                f'{safe_html(same_behavior.get("process_name", "-"))}'
                '&nbsp;&nbsp;/&nbsp;&nbsp;'
                f'파일 접근 {safe_html(same_behavior.get("file_access_count", 0))}'
                '&nbsp;&nbsp;/&nbsp;&nbsp;'
                f'USB {safe_html(same_behavior.get("usb_connected", 0))}<br>'
                '<span style="color:#64748b;">고정 Rule 근거 · '
                f'{safe_html(same_behavior.get("fixed_rule_reason", "-"))}'
                '</span></div>'
            ),
            unsafe_allow_html=True
        )

        office = adaptive_result.get("office_demo", {})
        flex = adaptive_result.get("flex_demo", {})
        left_demo, right_demo = st.columns(2)

        with left_demo:
            office_applied = bool(office.get("adaptive_applied", False))
            office_comp = float(office.get("adaptive_compensation", 0) or 0)
            office_reasons = office.get("baseline_reasons", [])
            office_reason_text = (
                " · ".join(str(item) for item in office_reasons)
                if office_reasons
                else "개인 기준선 이탈 근거 없음"
            )

            st.markdown(
                f"""
                <div class="adaptive-demo-card adaptive-demo-office">
                    <div class="adaptive-demo-type">{safe_html(office.get("user_type", "-"))}</div>
                    <div class="adaptive-demo-user">office_demo</div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">Baseline Score</span><span class="adaptive-demo-value">{safe_html(office.get("baseline_score", 0))}</span></div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">개인 기준선 판정</span><span class="adaptive-demo-value adaptive-demo-warn">{safe_html(office.get("judgment", "-"))}</span></div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">Baseline 신뢰도</span><span class="adaptive-demo-value">{safe_html(office.get("confidence_level", "-"))}</span></div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">Adaptive 보정</span><span class="adaptive-demo-value adaptive-demo-warn">-{office_comp:g} · {"적용" if office_applied else "미적용"}</span></div>
                    <div class="adaptive-demo-reason">{safe_html(office_reason_text)}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with right_demo:
            flex_applied = bool(flex.get("adaptive_applied", False))
            flex_comp = float(flex.get("adaptive_compensation", 0) or 0)
            flex_reasons = flex.get("adaptive_reasons", [])
            flex_reason_text = (
                " · ".join(str(item) for item in flex_reasons)
                if flex_reasons
                else "Adaptive 보정 근거 없음"
            )

            st.markdown(
                f"""
                <div class="adaptive-demo-card adaptive-demo-flex">
                    <div class="adaptive-demo-type">{safe_html(flex.get("user_type", "-"))}</div>
                    <div class="adaptive-demo-user">flex_demo</div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">Baseline Score</span><span class="adaptive-demo-value">{safe_html(flex.get("baseline_score", 0))}</span></div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">개인 기준선 판정</span><span class="adaptive-demo-value adaptive-demo-good">{safe_html(flex.get("judgment", "-"))}</span></div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">Baseline 신뢰도</span><span class="adaptive-demo-value">{safe_html(flex.get("confidence_level", "-"))}</span></div>
                    <div class="adaptive-demo-row"><span class="adaptive-demo-label">Adaptive 보정</span><span class="adaptive-demo-value adaptive-demo-good">-{flex_comp:g} · {"적용" if flex_applied else "미적용"}</span></div>
                    <div class="adaptive-demo-reason">{safe_html(flex_reason_text)}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        comparison = adaptive_result.get("comparison", {})
        st.markdown(
            (
                '<div class="learning-note"><b>보정 안전장치</b><br>'
                f'{safe_html(comparison.get("security_guard", "-"))}'
                '</div>'
            ),
            unsafe_allow_html=True
        )



# =========================================================
# PAGE 5
# CERT 100K 검증
# =========================================================


# =========================================================
# PAGE 5
# 행동 승인 관리 / Human-in-the-loop
# =========================================================

elif page == "행동 승인 관리":

    section_header(
        "Human-in-the-loop Behavior Review"
    )

    st.caption(
        "자동 UEBA가 OBSERVING 또는 REJECTED로 판정한 신규 행동을 "
        "SOC 관리자가 검토하고 정상 승인, 위험 유지 또는 재관찰로 "
        "수동 조정할 수 있습니다."
    )

    behavior_ok, behavior_changes = load_behavior_changes()

    if not behavior_ok:
        st.error(
            "행동 변화 검증 데이터를 불러오지 못했습니다. "
            "FastAPI 서버 상태를 확인하세요."
        )

    else:
        behavior_df = pd.DataFrame(
            behavior_changes
        )

        if behavior_df.empty:
            st.info(
                "현재 저장된 행동 변화 검증 항목이 없습니다."
            )

        else:
            # ---------------------------------------------
            # 상태 요약
            # ---------------------------------------------
            status_series = (
                behavior_df["status"]
                .astype(str)
                .str.upper()
                if "status" in behavior_df.columns
                else pd.Series(dtype=str)
            )

            observing_count = int(
                (status_series == "OBSERVING").sum()
            )
            accepted_count = int(
                (status_series == "ACCEPTED").sum()
            )
            rejected_count = int(
                (status_series == "REJECTED").sum()
            )

            manual_count = 0

            if "manual_override" in behavior_df.columns:
                manual_count = int(
                    pd.to_numeric(
                        behavior_df["manual_override"],
                        errors="coerce"
                    )
                    .fillna(0)
                    .astype(int)
                    .sum()
                )

            s1, s2, s3, s4 = st.columns(4)

            with s1:
                st.metric(
                    "관찰 중",
                    observing_count
                )

            with s2:
                st.metric(
                    "정상 승인",
                    accepted_count
                )

            with s3:
                st.metric(
                    "학습 제외",
                    rejected_count
                )

            with s4:
                st.metric(
                    "관리자 수동 판정",
                    manual_count
                )

            st.caption(
                "수동 승인 여부는 Behavior Change/Baseline 학습에만 "
                "반영되며 Rule · Sequence · Incident 탐지는 계속 동작합니다."
            )

            # ---------------------------------------------
            # 필터
            # ---------------------------------------------
            section_header(
                "검토 대상 필터"
            )

            f1, f2, f3 = st.columns(3)

            with f1:
                status_filter = st.selectbox(
                    "상태",
                    [
                        "전체",
                        "REJECTED",
                        "OBSERVING",
                        "ACCEPTED"
                    ],
                    key="behavior_review_status_filter"
                )

            with f2:
                user_values = [
                    "전체"
                ]

                if "user" in behavior_df.columns:
                    user_values += sorted(
                        behavior_df["user"]
                        .dropna()
                        .astype(str)
                        .unique()
                        .tolist()
                    )

                user_filter = st.selectbox(
                    "사용자",
                    user_values,
                    key="behavior_review_user_filter"
                )

            with f3:
                type_values = [
                    "전체"
                ]

                if "change_type" in behavior_df.columns:
                    type_values += sorted(
                        behavior_df[
                            "change_type"
                        ]
                        .dropna()
                        .astype(str)
                        .unique()
                        .tolist()
                    )

                type_filter = st.selectbox(
                    "행동 유형",
                    type_values,
                    key="behavior_review_type_filter"
                )

            filtered_behavior = behavior_df.copy()

            if (
                status_filter != "전체"
                and "status"
                in filtered_behavior.columns
            ):
                filtered_behavior = (
                    filtered_behavior[
                        filtered_behavior[
                            "status"
                        ]
                        .astype(str)
                        .str.upper()
                        == status_filter
                    ]
                )

            if (
                user_filter != "전체"
                and "user"
                in filtered_behavior.columns
            ):
                filtered_behavior = (
                    filtered_behavior[
                        filtered_behavior[
                            "user"
                        ].astype(str)
                        == user_filter
                    ]
                )

            if (
                type_filter != "전체"
                and "change_type"
                in filtered_behavior.columns
            ):
                filtered_behavior = (
                    filtered_behavior[
                        filtered_behavior[
                            "change_type"
                        ].astype(str)
                        == type_filter
                    ]
                )

            # ---------------------------------------------
            # 목록
            # ---------------------------------------------
            section_header(
                "행동 변화 검토 목록"
            )

            table_columns = [
                column
                for column in [
                    "id",
                    "user",
                    "change_type",
                    "change_value",
                    "status",
                    "seen_count",
                    "max_risk_score",
                    "manual_override",
                    "last_seen"
                ]
                if column in filtered_behavior.columns
            ]

            display_behavior = (
                filtered_behavior[
                    table_columns
                ].copy()
            )

            display_behavior = display_behavior.rename(
                columns={
                    "id": "ID",
                    "user": "사용자",
                    "change_type": "유형",
                    "change_value": "행동 값",
                    "status": "상태",
                    "seen_count": "관찰 횟수",
                    "max_risk_score": "최대 Risk",
                    "manual_override": "수동 판정",
                    "last_seen": "최근 관찰"
                }
            )

            if "수동 판정" in display_behavior.columns:
                display_behavior[
                    "수동 판정"
                ] = (
                    pd.to_numeric(
                        display_behavior[
                            "수동 판정"
                        ],
                        errors="coerce"
                    )
                    .fillna(0)
                    .astype(int)
                    .map({
                        0: "자동",
                        1: "관리자"
                    })
                    .fillna("자동")
                )

            st.dataframe(
                display_behavior,
                use_container_width=True,
                hide_index=True,
                height=310
            )

            # ---------------------------------------------
            # 관리자 판정
            # ---------------------------------------------
            section_header(
                "SOC 관리자 판정"
            )

            if filtered_behavior.empty:
                st.info(
                    "현재 필터 조건에 해당하는 항목이 없습니다."
                )

            else:
                select_options = {}

                for _, row in filtered_behavior.iterrows():
                    observation_id = row.get(
                        "id"
                    )

                    label = (
                        f"#{observation_id} · "
                        f"{row.get('user', '-')} · "
                        f"{row.get('change_type', '-')}="
                        f"{row.get('change_value', '-')} · "
                        f"{row.get('status', '-')}"
                    )

                    select_options[
                        label
                    ] = observation_id

                selected_label = st.selectbox(
                    "검토할 행동 선택",
                    list(
                        select_options.keys()
                    ),
                    key="behavior_review_selected"
                )

                selected_id = select_options[
                    selected_label
                ]

                selected_rows = (
                    behavior_df[
                        behavior_df["id"]
                        == selected_id
                    ]
                )

                if not selected_rows.empty:
                    selected = (
                        selected_rows
                        .iloc[0]
                        .to_dict()
                    )

                    d1, d2, d3, d4 = st.columns(
                        4
                    )

                    with d1:
                        st.metric(
                            "현재 상태",
                            selected.get(
                                "status",
                                "-"
                            )
                        )

                    with d2:
                        st.metric(
                            "관찰 횟수",
                            selected.get(
                                "seen_count",
                                0
                            )
                        )

                    with d3:
                        st.metric(
                            "최대 Risk",
                            selected.get(
                                "max_risk_score",
                                0
                            )
                        )

                    with d4:
                        st.metric(
                            "판정 주체",
                            (
                                "관리자"
                                if int(
                                    selected.get(
                                        "manual_override",
                                        0
                                    )
                                    or 0
                                ) == 1
                                else "자동 엔진"
                            )
                        )

                    st.markdown(
                        "**자동/수동 판정 사유**"
                    )

                    st.info(
                        str(
                            selected.get(
                                "decision_reason",
                                "-"
                            )
                            or "-"
                        )
                    )

                    existing_note = selected.get(
                        "manual_note"
                    )

                    has_existing_note = False

                    try:
                        has_existing_note = (
                            existing_note is not None
                            and not pd.isna(
                                existing_note
                            )
                            and str(
                                existing_note
                            ).strip() != ""
                        )
                    except Exception:
                        has_existing_note = (
                            existing_note is not None
                            and str(
                                existing_note
                            ).strip() != ""
                        )

                    if has_existing_note:
                        st.caption(
                            f"기존 관리자 메모: "
                            f"{existing_note}"
                        )

                    review_note = st.text_input(
                        "관리자 메모",
                        placeholder=(
                            "예: 정상적인 관리자 PowerShell 업무로 확인"
                        ),
                        key=(
                            f"behavior_note_"
                            f"{selected_id}"
                        )
                    )

                    a1, a2, a3 = st.columns(3)

                    with a1:
                        if st.button(
                            "정상 승인 · Whitelist",
                            use_container_width=True,
                            type="primary",
                            key=(
                                f"behavior_approve_"
                                f"{selected_id}"
                            )
                        ):
                            success, result = (
                                decide_behavior_change(
                                    selected_id,
                                    "approve",
                                    review_note
                                )
                            )

                            if success:
                                st.success(
                                    "정상 행동으로 승인했습니다. "
                                    "Baseline 학습 허용 상태로 변경됩니다."
                                )
                                st.rerun()

                            else:
                                st.error(
                                    result.get(
                                        "detail",
                                        "승인 처리 실패"
                                    )
                                )

                    with a2:
                        if st.button(
                            "위험 유지 · Reject",
                            use_container_width=True,
                            key=(
                                f"behavior_reject_"
                                f"{selected_id}"
                            )
                        ):
                            success, result = (
                                decide_behavior_change(
                                    selected_id,
                                    "reject",
                                    review_note
                                )
                            )

                            if success:
                                st.success(
                                    "위험 행동으로 유지했습니다. "
                                    "정상 Baseline 학습에서 제외됩니다."
                                )
                                st.rerun()

                            else:
                                st.error(
                                    result.get(
                                        "detail",
                                        "위험 유지 처리 실패"
                                    )
                                )

                    with a3:
                        if st.button(
                            "재관찰 · Reset",
                            use_container_width=True,
                            key=(
                                f"behavior_reset_"
                                f"{selected_id}"
                            )
                        ):
                            success, result = (
                                decide_behavior_change(
                                    selected_id,
                                    "reset",
                                    review_note
                                )
                            )

                            if success:
                                st.success(
                                    "수동 판정을 해제하고 "
                                    "OBSERVING 상태로 되돌렸습니다."
                                )
                                st.rerun()

                            else:
                                st.error(
                                    result.get(
                                        "detail",
                                        "재관찰 처리 실패"
                                    )
                                )


elif page == "CERT 100K 검증":

    section_header("평가 데이터 구성")

    st.caption(
        "CERT Insider Threat Dataset r4.2에서 logon · device · file 이벤트를 "
        "공통 스키마로 변환하여 100,000건의 통제된 평가 샘플을 구성했습니다."
    )

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "평가 이벤트",
            "100,000"
        )

    with c2:
        st.metric(
            "악성 이벤트",
            "2,993"
        )

    with c3:
        st.metric(
            "정상 이벤트",
            "97,007"
        )

    with c4:
        st.metric(
            "탐지 Threshold",
            "24"
        )

    st.info(
        "평가 샘플은 CERT 원본 분포 그대로가 아니라, "
        "선택한 악성 이벤트 2,993건을 모두 포함하고 정상 이벤트를 무작위 샘플링한 "
        "통제된 100K 평가셋입니다."
    )


    section_header("Confusion Matrix")

    confusion_df = pd.DataFrame(
        [
            {
                "실제 / 예측": "실제 악성",
                "위험 탐지": 552,
                "정상 판정": 2441
            },
            {
                "실제 / 예측": "실제 정상",
                "위험 탐지": 5619,
                "정상 판정": 91388
            }
        ]
    )

    st.dataframe(
        confusion_df,
        use_container_width=True,
        hide_index=True
    )

    cm1, cm2, cm3, cm4 = st.columns(4)

    with cm1:
        st.metric(
            "TP",
            "552",
            help="실제 악성 이벤트를 위험으로 탐지"
        )

    with cm2:
        st.metric(
            "FP",
            "5,619",
            help="정상 이벤트를 위험으로 탐지"
        )

    with cm3:
        st.metric(
            "TN",
            "91,388",
            help="정상 이벤트를 정상으로 판정"
        )

    with cm4:
        st.metric(
            "FN",
            "2,441",
            help="악성 이벤트를 정상으로 판정"
        )


    section_header("이벤트 단위 성능")

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric(
            "Precision",
            "8.95%"
        )

    with m2:
        st.metric(
            "Recall",
            "18.44%"
        )

    with m3:
        st.metric(
            "False Positive Rate",
            "5.79%"
        )

    with m4:
        st.metric(
            "F1 Score",
            "12.05%"
        )

    st.warning(
        "이벤트 단위 Recall은 낮습니다. CERT 라벨은 하나의 공격 시나리오 안에서도 "
        "여러 하위 이벤트를 각각 악성으로 표시하지만, SENTINEL은 모든 하위 이벤트를 "
        "독립 경보로 발생시키기보다 의미 있는 위험 흐름과 핵심 이벤트를 선택적으로 탐지하도록 설계했습니다."
    )


    section_header("공격 시나리오 단위 탐지")

    scenario1, scenario2, scenario3 = st.columns(3)

    with scenario1:
        st.metric(
            "전체 공격 시나리오",
            "70"
        )

    with scenario2:
        st.metric(
            "탐지 시나리오",
            "70"
        )

    with scenario3:
        st.metric(
            "Scenario Detection",
            "100%"
        )

    st.success(
        "Threshold 24 기준으로 각 CERT 공격 시나리오에서 "
        "최소 1개 이상의 라벨된 악성 이벤트가 탐지되어 70/70 시나리오를 식별했습니다."
    )

    st.caption(
        "※ 이는 '모든 악성 이벤트를 100% 탐지했다'는 의미가 아닙니다. "
        "각 공격 시나리오에서 최소 1개 이상의 핵심 악성 이벤트를 탐지했다는 의미입니다."
    )


    section_header("Threshold 선택 근거")

    threshold_df = pd.DataFrame(
        [
            {
                "Threshold": 23.0,
                "Recall (%)": 27.00,
                "FPR (%)": 8.64,
                "Scenario Detection (%)": 100.00
            },
            {
                "Threshold": 23.5,
                "Recall (%)": 22.08,
                "FPR (%)": 7.35,
                "Scenario Detection (%)": 100.00
            },
            {
                "Threshold": 24.0,
                "Recall (%)": 18.44,
                "FPR (%)": 5.79,
                "Scenario Detection (%)": 100.00
            },
            {
                "Threshold": 24.5,
                "Recall (%)": None,
                "FPR (%)": 5.42,
                "Scenario Detection (%)": 98.57
            },
            {
                "Threshold": 25.0,
                "Recall (%)": None,
                "FPR (%)": 5.09,
                "Scenario Detection (%)": 97.14
            },
            {
                "Threshold": 26.0,
                "Recall (%)": None,
                "FPR (%)": 3.06,
                "Scenario Detection (%)": 90.00
            },
            {
                "Threshold": 27.0,
                "Recall (%)": None,
                "FPR (%)": 1.89,
                "Scenario Detection (%)": 87.14
            },
            {
                "Threshold": 30.0,
                "Recall (%)": 3.68,
                "FPR (%)": 0.35,
                "Scenario Detection (%)": 52.86
            }
        ]
    )

    st.dataframe(
        threshold_df,
        use_container_width=True,
        hide_index=True
    )

    chart_df = threshold_df[
        [
            "Threshold",
            "FPR (%)",
            "Scenario Detection (%)"
        ]
    ].copy()

    chart_df = chart_df.set_index(
        "Threshold"
    )

    st.line_chart(
        chart_df,
        height=320
    )

    st.markdown(
        "**Threshold 24 선택 이유**"
    )

    st.markdown(
        "- Threshold를 24보다 높이면 오탐률은 더 감소하지만 공격 시나리오 탐지율이 떨어지기 시작합니다."
    )

    st.markdown(
        "- Threshold 24에서는 Scenario Detection 100%를 유지하면서 FPR을 5.79%까지 낮췄습니다."
    )

    st.markdown(
        "- 따라서 현재 SENTINEL은 공격 흐름 보존과 오탐 억제 사이의 균형점으로 24를 사용합니다."
    )


    section_header("검증 결과 해석")

    interpretation_df = pd.DataFrame(
        [
            {
                "평가 관점": "대규모 처리",
                "결과": "100,000건 처리 완료",
                "해석": "교수 피드백의 10만 건 이상 데이터 검증 조건 충족"
            },
            {
                "평가 관점": "이벤트 단위 탐지",
                "결과": "Recall 18.44%",
                "해석": "모든 악성 하위 이벤트를 개별 경보로 탐지하지는 않음"
            },
            {
                "평가 관점": "오탐",
                "결과": "FPR 5.79%",
                "해석": "Threshold 30 대비 탐지 민감도를 높인 만큼 일부 정상 이벤트 오탐 존재"
            },
            {
                "평가 관점": "공격 흐름 탐지",
                "결과": "70/70 · 100%",
                "해석": "모든 평가 공격 시나리오에서 최소 1개 이상의 핵심 악성 이벤트 탐지"
            },
            {
                "평가 관점": "향후 개선",
                "결과": "Precision 8.95%",
                "해석": "행동 기준선과 맥락 검증을 추가 학습하여 오탐을 더 줄일 필요"
            }
        ]
    )

    st.dataframe(
        interpretation_df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "평가 기준 · CERT r4.2 통제 샘플 100,000건 · "
        "Threshold 24 · 이벤트 단위 및 시나리오 단위 평가 병행"
    )



# =========================================================
# Footer
# =========================================================

footer_html = """
<div style="
border-top:1px solid #1b2532;
margin-top:32px;
padding-top:13px;
color:#435064;
font-size:9px;
display:flex;
justify-content:space-between;">
<span>
SENTINEL · 내부자 위협 탐지 및 대응 플랫폼
</span>
<span>
RULE · ML · UEBA · SEQUENCE · PII · LLM
</span>
</div>
"""

st.markdown(
    footer_html,
    unsafe_allow_html=True
)

