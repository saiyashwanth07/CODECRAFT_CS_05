pip install scapy matplotlib
from scapy.all import sniff, IP, TCP, Raw
import matplotlib.pyplot as plt

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Packet: Source Port {tcp_layer.sport}, Destination Port {tcp_layer.dport}")

            if Raw in packet:
                raw_layer = packet[Raw].load
                print(f"Payload: {raw_layer[:50]}...")  # Display the first 50 characters of the payload

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()