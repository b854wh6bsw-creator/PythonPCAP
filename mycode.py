import sys
import argparse
from datetime import datetime
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, SCTP


def get_packet_details(pkt):
    """Extracts addresses, protocols, and ports for IP or ARP packets."""
    src_ip, dst_ip, proto, sport, dport = "-", "-", "Other", "-", "-"

    # 1. Handle IP/IPv6 Traffic
    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        if pkt.haslayer(TCP):
            proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        elif pkt.haslayer(SCTP):
            proto, sport, dport = "SCTP", pkt[SCTP].sport, pkt[SCTP].dport

    # 2. Handle ARP Traffic (Layer 2)
    elif pkt.haslayer(ARP):
        arp_layer = pkt[ARP]
        src_ip = arp_layer.psrc  # Sender Protocol Address (IP)
        dst_ip = arp_layer.pdst  # Target Protocol Address (IP)
        # ARP Opcode 1 is 'who-has' (request), 2 is 'is-at' (reply)
        proto = f"ARP ({'Req' if arp_layer.op == 1 else 'Reply'})"
        sport = arp_layer.hwsrc  # Extra info: Sender MAC in SPort column
        dport = arp_layer.hwdst  # Extra info: Target MAC in DPort column

    return src_ip, dst_ip, proto, sport, dport


def analyze_pcap(file_path):
    # Professional Header Structure as requested
    header = f"{'#':>4} | {'Timestamp':<24} | {'Src IP':<25} | {'Dst IP':<25} | {'Proto':<10} | {'Len':<6} | {'SPort':<18} | {'DPort':<18}"
    print(header)
    print("-" * len(header))

    try:
        with PcapReader(file_path) as pcap_stream:
            for idx, pkt in enumerate(pcap_stream, start=1):
                # Only process IP or ARP packets
                if not (pkt.haslayer(IP) or pkt.haslayer(IPv6) or pkt.haslayer(ARP)):
                    continue

                ts = datetime.fromtimestamp(float(pkt.time)).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                length = getattr(pkt, 'wirelen', len(pkt))
                src, dst, proto, sport, dport = get_packet_details(pkt)

                print(f"{idx:>4} | {ts:<24} | {src:<25} | {dst:<25} | "
                      f"{proto:<10} | {length:<6} | {str(sport):<18} | {str(dport):<18}")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional PCAP Analyzer (IP & ARP)")
    parser.add_argument("file", help="Input .pcap file")
    args = parser.parse_args()
    analyze_pcap(args.file)
