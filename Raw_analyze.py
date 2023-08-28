#window_size 출력...
#IPv4 헤더: 20 바이트
#TCP 헤더: 최소 20 바이트 (옵션을 포함하면 더 길어질 수 있음.)
#TCP 헤더 내의 윈도우 사이즈 필드는 16비트로, TCP 헤더의 14번째와 15번째 바이트에 위치.

import socket
import struct

IPV4_HEADER_SIZE = 20
TCP_HEADER_SIZE = 20

# 소켓 생성
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    packet, addr = s.recvfrom(4096)  # 패킷 수신

    # IP 헤더 길이
    total_length = struct.unpack('!H', packet[2:4])[0]
    
    # TCP 헤더 헤더 길이 추출
    data_offset = (packet[IPV4_HEADER_SIZE + 12] >> 4) * 4

    # TCP 페이로드 시작 위치 계산
    start = IPV4_HEADER_SIZE + data_offset
    tcp_payload = packet[start:IPV4_HEADER_SIZE + total_length]

    if tcp_payload:  # 페이로드가 있다면 출력
        print(f"{addr[0]} - TCP payload : {tcp_payload}")

        # 소켓 오류....