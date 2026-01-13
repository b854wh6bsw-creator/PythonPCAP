import sys
import argparse
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP


def get_protocol_name(pkt, ip_layer):
    """Determine human-readable protocol name."""
    if TCP in pkt: return "TCP"
    if UDP in pkt: return "UDP"
    if ICMP in pkt: return "ICMP"

    # Handle protocol number fallback for IP and IPv6
    proto_num = getattr(ip_layer, 'proto', getattr(ip_layer, 'nh', "??"))
    return f"P-{proto_num}"


def get_ports(pkt):
    """Return source and destination ports or '-' if not TCP/UDP."""
    layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
    if layer:
        return layer.sport, layer.dport
    return "-", "-"


def analyze_pcap(file_path):
    """Processes packets one-by-one to ensure low memory footprint."""
    header = f"{'#':>5} | {'Src IP':<25} | {'Dst IP':<25} | {'Proto':<8} | {'Len':<6} | {'SPort':<6} | {'DPort':<6}"
    print(f"\nAnalyzing: {file_path}")
    print("-" * len(header))
    print(header)
    print("-" * len(header))

    total_pkts = 0
    ip_pkts = 0

    try:
        # PcapReader is the professional choice for large files in 2026
        with PcapReader(file_path) as pcap_stream:
            for idx, pkt in enumerate(pcap_stream, start=1):
                total_pkts += 1

                # Check for IP or IPv6 layers
                ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)

                if ip_layer:
                    ip_pkts += 1
                    # wirelen is the actual size captured on the cable
                    length = getattr(pkt, 'wirelen', len(pkt))
                    proto = get_protocol_name(pkt, ip_layer)
                    sport, dport = get_ports(pkt)

                    print(f"{idx:>5} | {ip_layer.src:<25} | {ip_layer.dst:<25} | "
                          f"{proto:<8} | {length:<6} | {sport:<6} | {dport:<6}")

        print("-" * len(header))
        print(f"Summary: {ip_pkts} IP packets identified out of {total_pkts} total.")

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"Analysis Error: {e}")


if __name__ == "__main__":
    # Use argparse for better CLI experience (standard for 2026 tools)
    parser = argparse.ArgumentParser(description="Professional PCAP IP/Port Analyzer")
    parser.add_argument("file", help="Path to the PCAP file")

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    analyze_pcap(args.file)
