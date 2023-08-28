from concurrent.futures import ThreadPoolExecutor
from scapy.all import rdpcap, IP, TCP
import threading

detected = threading.Event()

# Snort 규칙 읽기
def read_snort_rules(filename):
    rules = []
    try:
        with open(filename, "r") as rulefile:
            for line in rulefile:
                if not line.startswith("#") and line.strip():
                    parts = line.strip().split(" ")
                    action, proto, src_ip, src_port, direction, dst_ip, dst_port = parts[:7]
                    options = " ".join(parts[7:])
                    rules.append({
                        'action': action,
                        'proto': proto,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'direction': direction,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'options': options
                    })
    except Exception as e:
        print(f"An error occurred: {e}")
    return rules

# 패킷 분석 함수
def analyze_packet(pkt, rules):
    global detected
    if IP not in pkt or TCP not in pkt:
        return
    
    for rule in rules:
        if rule['proto'] == 'tcp':
            if all([
                pkt[IP].dst == rule['dst_ip'] or rule['dst_ip'] == 'any',
                str(pkt[TCP].dport) == rule['dst_port'] or rule['dst_port'] == 'any'
            ]):
                if 'content' in rule['options']:
                    content_value = rule['options'].split('content:"')[1].split('";')[0]
                    if content_value.encode() in bytes(pkt[TCP].payload):
                        print(f"악성 패킷 탐지: {rule}")
                        detected.set()
                        return

# 청크로 나누기
def divide_chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

if __name__ == "__main__":
    rules = read_snort_rules("C:/Python/Network_packet_analyzer/snort3_community.rules")
    packets = rdpcap("C:/Python/Network_packet_analyzer/capture.pcap")

    # 패킷을 청크로 나눕니다. 여기서는 청크 크기를 1000으로 설정했습니다.
    packet_chunks = list(divide_chunks(packets, 1000))

    detected = False
    # 병렬 처리 시작
    with ThreadPoolExecutor() as executor:
        for chunk in packet_chunks:
            executor.submit(lambda pkt_chunk: [analyze_packet(pkt, rules) for pkt in pkt_chunk], chunk)

    if not detected.is_set():
        print("악성 패킷을 탐지하지 못했습니다.")