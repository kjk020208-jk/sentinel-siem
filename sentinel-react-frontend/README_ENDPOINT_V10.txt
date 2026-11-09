SENTINEL React v10 Endpoint Behavior Integration

- /behavior-changes 결과와 /users/{user}/endpoint-profile observations 병합
- ENDPOINT_NETWORK / AGENT_ID 누락 방지
- 같은 observation id는 중복 제거
- Endpoint 행도 기존 /behavior-changes/{id}/decision API로 Whitelist/Reject/Reset 가능
- SOC 관리자 판정의 관찰 횟수에 seen_count 반영

적용:
기존 siemueba/sentinel-react-frontend 폴더에 이 폴더 내용을 덮어쓴 후 npm.cmd run dev 재실행.
