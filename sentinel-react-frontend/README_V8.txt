SENTINEL React v8

주요 변경:
- 학습 프로필 빈 배열은 '학습 데이터 부족' 표시
- Dynamic Risk 행동 유형/기여도, 최근 기여 행동 추이, Event Risk 시간 추이를 Plotly로 교체
- Plotly hover, zoom, pan, autoscale, 축 라벨 지원
- Overview 도넛 차트를 Plotly pie/donut으로 교체하여 퍼센트 라벨 + hover tooltip 제공
- 행동 변화 검토 목록 고정 높이 내부 스크롤
- 보안 사고 분석 순서: Incident -> Storyline -> Incident AI -> SOAR -> 연관 이벤트 -> 개별 이벤트 분석

실행:
$env:Path += ";C:\Program Files\nodejs"
npm.cmd install
npm.cmd run dev
