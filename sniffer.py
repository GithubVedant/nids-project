from scapy.all import sniff, IP
from collections import defaultdict
import time

packet_count = defaultdict(int)
THRESHOLD = 20 # packets threshold for alert

def detect_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_count[src_ip] += 1
        
        if packet_count[src_ip] > THRESHOLD:
            alert = f"[ALERT] Possible port scan detected from {src_ip}"
            print(alert)
            
            with open("alerts.txt", "a") as f:
                f.write(alert + "\n")

def start_sniffing():
    print("Starting network monitoring...")
    sniff(prn=detect_packet, store=0)

if __name__ == "__main__":
    start_sniffing()