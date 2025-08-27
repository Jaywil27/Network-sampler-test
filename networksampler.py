from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, ICMP
import requests
import json

def query_ollama3b(prompt):
    url = "http://localhost:11434/api/generate"
    payload = {
    "model": "llama3.1",
    "prompt": prompt,
    "stream": False
    }
    response = requests.post(url, json=payload)
    answer = response.json()["response"]
    return answer

PORT_PROTOCOLS = {
    443: "QUIC",
    80: "HTTP",
    53: "DNS",
    123: "NTP",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    995: "POP3S",
    993: "IMAPS",
}

def packet_summary(pkt):
 
    layers = []
    current_layer = pkt
    while current_layer:
        layers.append(current_layer.__class__.__name__)
        current_layer = current_layer.payload
        if current_layer is None or current_layer.__class__.__name__ == "NoPayload":
            break

    if pkt.haslayer(Ether):
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
    else:
        src_mac = dst_mac = "N/A"


    src_ip = getattr(pkt, "src", "N/A")
    dst_ip = getattr(pkt, "dst", "N/A")

    proto = ""
    info = ""
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        proto = PORT_PROTOCOLS.get(tcp.sport, PORT_PROTOCOLS.get(tcp.dport, "TCP"))
        info = f"{tcp.sport} -> {tcp.dport}"
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        proto = PORT_PROTOCOLS.get(udp.sport, PORT_PROTOCOLS.get(udp.dport, "UDP"))
        info = f"{udp.sport} -> {udp.dport}"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        info = f"Type {pkt[ICMP].type}"
    elif pkt.haslayer(ARP):
        proto = "ARP"
        info = f"{pkt[ARP].psrc} -> {pkt[ARP].pdst}"
    else:
        proto = pkt.__class__.__name__

    return {
        "layers": layers,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "info": info,
        "protocol": proto
    }


packets = sniff(count=50, iface="Ethernet")
samples = packets[::5]


packet_data = [packet_summary(pkt) for pkt in samples]

for data in packet_data:
    print(data)


print(query_ollama3b(f"Analyze the packets and explain them and whether they are malicious and what they are doing {packet_data}"))
