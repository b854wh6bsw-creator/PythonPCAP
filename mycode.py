# mycode.py
# Enhanced PCAP analyzer: shows Src IP, Dst IP, Protocol, Packet Length (on wire),
# and Source/Dest Ports (when TCP or UDP is present)
#
# Improvements from previous version:
# - Added pkt.wirelen → real captured packet length on the wire (most useful/accurate)
# - Added sport/dport extraction for TCP & UDP (most common transport protocols)
# - Clean formatting with aligned columns
# - Shows '-' when ports are not applicable (ICMP, ESP, etc.)
#
# Note: Install scapy if not already: pip install scapy

import sys
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP

def get_protocol(pkt, ip_layer):
    """Determine human-readable protocol name"""
    if TCP in pkt:
        return "TCP"
    elif UDP in pkt:
        return "UDP"
    elif ICMP in pkt:
        return "ICMP"
    else:
        # Fallback to protocol number (good for exotic protocols)
        proto_num = ip_layer.proto if hasattr(ip_layer, 'proto') else ip_layer.nh
        return f"Other({proto_num})"


def get_ports(pkt):
    """Return source and destination ports or '-' if not TCP/UDP"""
    if TCP in pkt:
        return pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        return pkt[UDP].sport, pkt[UDP].dport
    else:
        return "-", "-"


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 mycode.py file.pcap")
        sys.exit(1)

    pcap_file = sys.argv[1]

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        sys.exit(1)

    # Header
    print("\nPCAP Analysis - Basic IP/TCP/UDP information")
    print("-" * 85)
    print(f"{'#':>4} | {'Src IP':<15} | {'Dst IP':<15} | {'Proto':<6} | "
          f"{'Length':<6} | {'Sport':<6} | {'Dport':<6}")
    print("-" * 85)

    ip_packet_count = 0

    for idx, pkt in enumerate(packets, start=1):
        # Get real packet length on wire (most accurate)
        length = pkt.wirelen if hasattr(pkt, 'wirelen') else len(pkt)

        ip_layer = None
        if IP in pkt:
            ip_layer = pkt[IP]
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]

        if ip_layer:
            ip_packet_count += 1
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = get_protocol(pkt, ip_layer)
            sport, dport = get_ports(pkt)

            print(f"{idx:>4} | {src_ip:<15} | {dst_ip:<15} | {proto:<6} | "
                  f"{length:>6} | {sport:>6} | {dport:>6}")

    print("-" * 85)
    print(f"Total packets in file: {len(packets)}")
    print(f"IP packets analyzed:  {ip_packet_count}")


if __name__ == "__main__":
    main()
