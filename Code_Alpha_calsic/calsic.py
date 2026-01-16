# =================   Calsic Network Sniffer =================  

from scapy.all import sniff , IP , TCP , UDP , ICMP , Raw 

def process_packet(packet):
    if IP in packet:
        print("\n" + "=" * 60)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        print(f"Source IP  : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        # Protocol Handling 
        if packet.haslayer(TCP):
            print("Protocol : TCP ")
            print(f" Source Port  : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print (f"Protocol : UDP ")
            print(f"Source Port : {packet[UDP].sport} ")
            print(f"Destination Port : {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
             print (f" Protocol  : ICMP ")
        
        # Payload 
        if packet.haslayer(Raw):
             payload = packet[Raw].load
             print(f"Payload    : {payload[:100]}") #Limit of output 

def start_sniffing():
     print("Starting Network Sniffing ........")
     print("Press CTRL + C to stop \n ")
     sniff(prn=process_packet , store=False)

if __name__ == "__main__": 
    start_sniffing()
