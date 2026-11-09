# SENTINEL React Full Feature Clone

기준: 기존 Streamlit `dashboard/app.py` 화면/기능 구조.

포함 기능
- 보안 현황: Live Critical, Live Event, KPI, 위험 등급/이벤트 유형/평균 위험도, TOP 이벤트/사용자, 행동 변화 현황, 경보, 최근 이벤트, 운영 성능
- 이벤트 모니터링: 위험등급/사용자/유형/검색 필터, 이벤트 로그, 행동 변화 검증, Explainable Risk Score, 개별 이벤트 AI 분석
- 보안 사고 분석: Incident 필터/선택, Correlation 요약, Attack Storyline, Incident AI SOC, SOAR-lite Playbook 단계 승인/거부/재검토, 연관 이벤트, 개별 이벤트 분석
- 사용자 행동 분석: 모니터링 사용자 등록/활성/비활성/삭제, Behavior Profile, Dynamic User Risk, 사용자 활동 이력, Adaptive Personal UEBA 비교 시연
- 행동 승인 관리: 상태/사용자/유형 필터, 상세 검토, 관리자 메모, Whitelist/Reject/Reset
- CERT 100K 검증: 데이터 구성, Confusion Matrix, 이벤트 단위 성능, 시나리오 탐지, Threshold 비교, 결과 해석
- 사이드바: 정상/공격 시나리오, 초기화 확인, 실시간 자동 갱신, 수동 새로고침

실행
1. FastAPI: uvicorn server.main:app --reload --host 127.0.0.1 --port 8000
2. Windows Collector: python -m client.windows_collector
3. React:
   cd sentinel-react-frontend
   $env:Path += ";C:\Program Files\nodejs"
   npm.cmd install
   npm.cmd run dev
4. http://localhost:5173
