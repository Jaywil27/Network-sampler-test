from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, ICMP

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
    # Get layers
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

    print(f"Layers: {' -> '.join(layers)} | MAC: {src_mac} -> {dst_mac} | IP: {src_ip} -> {dst_ip} | Info: {info} | Protocol: {proto}")

packets = sniff(count=50, iface="Ethernet")
samples = packets[::5]

for pkt in samples:
    packet_summary(pkt)



