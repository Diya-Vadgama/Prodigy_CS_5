from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    
    Args:
        packet: The packet captured by Scapy.
    """
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Determine protocol type
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

        print(f"Packet Captured:")
        print(f"- Source IP: {src_ip}")
        print(f"- Destination IP: {dst_ip}")
        print(f"- Protocol: {protocol_name}")

        # Display payload if present
        if protocol_name in ["TCP", "UDP"] and packet[protocol_name].payload:
            payload = bytes(packet[protocol_name].payload)
            print(f"- Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
        print("-" * 50)


def main():
    print("Packet Sniffer Tool (Press Ctrl+C to stop)")
    print("Capturing packets...")

    # Start sniffing
    try:
        sniff(prn=packet_callback, filter="ip", store=0)
    except KeyboardInterrupt:
        print("\nStopping packet capture. Goodbye!")


if __name__ == "__main__":
    main()
