# =================   Classic Network Sniffer =================

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

packet_count = 0  # Counter for captured packets

def process_packet(packet):
    global packet_count
    packet_count += 1

    if IP in packet:
        print("\n" + "=" * 60)
        print(f"Packet No      : {packet_count}")

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        # Protocol Handling
        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Dest Port      : {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Dest Port      : {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        # Payload (limited for readability)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload        : {payload[:100]}")

def start_sniffing():
    print("Starting Network Sniffing...")
    print("Press CTRL + C to stop\n")

    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
# =================   Classic Network Sniffer =================