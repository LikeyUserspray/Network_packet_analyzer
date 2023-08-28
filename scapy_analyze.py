from scapy.all import *
from scapy.all import TCP, IP


#버퍼 초기화
buffer = None

def packet_tcp(packet):
    if TCP in packet:
        # TCP 헤더에서 윈도우 사이즈 추출
        window_size = packet[TCP].window
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        seq = packet[TCP].seq
        ack = packet[TCP].ack
        flags = packet[TCP].flags
        buffer = bytearray(window_size)
        #print(f"버퍼크기조정: {len(buffer)}")
        payload = packet[TCP].payload
        header_length = packet[TCP].dataofs*4
        
        print(f"Source : {src_ip}:{src_port} |  Destination : {dst_ip}:{dst_port}")
        print(f"seq_num : {seq} | ack : {ack}")
        print(f"header_length : {header_length} bytes | flag : {flags} | window_size : {window_size}")

        
        if payload:
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                print(f"Payload : {raw_data}")
        
        print("=======================================================================================================")


"""
def packet_icmp(packet):
    if ICMP in packet:
        print(packet.summary())
    else:
        return
"""        


# 패킷 캡처 시작
sniff(filter="tcp", prn=packet_tcp, count=2, timeout=3)
"""
sniff(filter="icmp", prn=packet_icmp ,count=10, timeout=3)
"""