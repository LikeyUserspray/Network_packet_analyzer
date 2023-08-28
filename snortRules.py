from scapy.all import sniff, IP, TCP
import re

def read_rules(filename):
    rules = []
    with open(filename, "r") as f:
        lines = f.readlines()
        for line in lines:
            if not line.startswith("#") and "alert" in line:  # Comment and empty lines skip
                tokens = line.split(";")
                protocol = tokens[0].split(" ")[1]
                msg = re.search('msg:"(.*?)",', line).group(1) if re.search('msg:"(.*?)",', line) else None
                content = re.search('content:"(.*?)",', line).group(1) if re.search('content:"(.*?)",', line) else None
                rules.append({
                    'protocol': protocol,
                    'msg': msg,
                    'content': content
                })
    return rules

def packet_callback(pkt):
    if IP not in pkt or TCP not in pkt:
        return
    
    for rule in rules:
        payload = str(pkt[TCP].payload)
        if rule['content'] and rule['content'].encode() in payload.encode():
            print(f"Malicious packet detected: {rule}")

if __name__ == "__main__":
    rules = read_rules("snort3_community.rules")
    sniff(filter="ip", prn=packet_callback)
