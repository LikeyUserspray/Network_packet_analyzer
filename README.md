# Network_packet_analyzer
mini_wireshark, snort rules, current malicious_ip ids with urlhuas

네트워크 패킷 분석 및 IDS 시스템 기능

구현 

![2g3g42g3](https://github.com/LikeyUserspray/Network_packet_analyzer/assets/98539049/73d18f29-b0a6-4055-a872-43a3e7799334)


미니 와이어샤크의 기능처럼...
1. 실시간 로컬 환경의 트래픽 탐지
2. pcap 파일 분석(pcap 파일 업로드 시... urlhaus API로 바로 연결되어 최신의 악성 ip나 도메인이 없는지 확인)
3. Visualization을 통한 악성 패킷과 정상 패킷의 갯수 통계 시각화
4. 와이어 샤크 처럼 각 패킷 클릭 시 패킷의 세부 내용 볼 수 있도록 출력.

의도했던 IDS 기능
- 머신러닝을 통한 악성 트래픽 탐지
- snort rule에 걸리는 패킷이 있는지 탐지
- urlhaus 사이트 기반 최신 악성 ip나 도메인 탐지

그러나, snort rule 의 개별 실행은 완료하였으나, 코드 통합에서 프로그램이 다운 되는 오류가 발생하여 아직 수정 중에 있습니다....
머신러닝의 경우 데이터 셋의 부족과 학습 모델의 신뢰성 문제가 있다고 판단하여 해당 기능을 제외하였습니다.
