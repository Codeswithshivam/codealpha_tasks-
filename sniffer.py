from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

PACKET_LIMIT = 30


def analyze_packet(packet):
    """Display useful metadata about one captured IPv4 packet."""
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        payload_size = len(bytes(packet[TCP].payload))
    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        payload_size = len(bytes(packet[UDP].payload))
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        source_port = "-"
        destination_port = "-"
        payload_size = len(bytes(packet[ICMP].payload))
    else:
        protocol = f"IP protocol {ip_layer.proto}"
        source_port = "-"
        destination_port = "-"
        payload_size = len(bytes(ip_layer.payload))

    print("-" * 55)
    print("Time:", datetime.now().strftime("%H:%M:%S"))
    print("Source IP:", source_ip)
    print("Destination IP:", destination_ip)
    print("Protocol:", protocol)
    print("Source Port:", source_port)
    print("Destination Port:", destination_port)
    print("Payload Size:", payload_size, "bytes")
    print("Packet Summary:", packet.summary())


def main():
    print("=" * 55)
    print("       BASIC PYTHON NETWORK SNIFFER")
    print("=" * 55)
    print(f"Capturing up to {PACKET_LIMIT} IPv4 packets.")
    print("Metadata only. Press Ctrl+C to stop early.")
    print("Capture only traffic you are authorized to inspect.\n")

    try:
        sniff(
            filter="ip",
            prn=analyze_packet,
            count=PACKET_LIMIT,
            store=False
        )
        print("\nCapture completed.")
    except PermissionError:
        print("Permission denied. Check capture permissions.")
    except OSError as error:
        print("Capture error:", error)
        print("Check Npcap, permissions, and network interface settings.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")


if __name__ == "__main__":
    main()
