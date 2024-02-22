from scapy.all import sniff, IP, TCP

# Define the packet processing callback
def process_packet(packet):
    # Check for IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Packet: {ip_src} -> {ip_dst}")

        # Check for TCP layer
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"TCP Packet: Src Port: {tcp_sport}, Dst Port: {tcp_dport}")

            # Check for payload (data)
            if packet[TCP].payload:
                payload = packet[TCP].load
                try:
                    # Attempt to decode payload
                    decoded_payload = payload.decode('utf-8')
                    print(f"Payload: {decoded_payload}")
                except UnicodeDecodeError:
                    # Payload might not be text-based; print a hexdump for analysis
                    print("Payload contains non-text data.")
                    packet[TCP].payload.show()

def main():
    print("Starting packet capture... Press CTRL+C to stop.")
    # Start sniffing packets
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
