from urllib.parse import urlparse
from scapy.all import sniff, IP, TCP

# snort 규칙은 보통 다음과 같은 형식을 가진다. 
# action proto src_ip src_port direction dst_ip dst_port (options)
# = alert tcp any any -> 192.168.1.0/24 80 (content:"GET";)

# 이 코드는 실시간 트래픽에 대한 스노트룰 기반 탐지이다.
# 스노트 룰 파일에 대한 권한이 필요하다. chmod 740? 사실 어느정도 필요한지는 모르겠다...그냥 777 놓고 돌린다...

def read_snort_rules(filename):
    rules = []
    try:
        with open(filename, "r") as rulefile:
            for line in rulefile:
                if not line.startswith("#") and line.strip():  # Skip comments and empty lines
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

def packet_callback(pkt):
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

if __name__ == "__main__":
    rules = read_snort_rules("c:/Python/Network_packet_analyzer/snort3_community.rules")
    sniff(filter="ip", prn=packet_callback)
