import os
import sys
import json
import time
import argparse
from datetime import datetime
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, SCTP
from elasticsearch import Elasticsearch
from prometheus_client import start_http_server, Counter, Histogram, Gauge

# --- 1. Configuration ---
ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "pcap_index")
METRICS_PORT = int(os.getenv("ENV_METRICS_PORT", 9100))
FAILED_LOG = "failed_ingestion.jsonl"

# --- 2. Metrics ---
NAMESPACE = "pcap"
PACKETS_TOTAL = Counter(f'{NAMESPACE}_packets_total', 'Total packets', ['protocol', 'version'])
BYTES_TOTAL = Counter(f'{NAMESPACE}_bytes_total', 'Total bytes', ['protocol'])
ELASTIC_INGESTION_TOTAL = Counter(f'{NAMESPACE}_elastic_ingestion_total', 'Status', ['status'])
SUSPICIOUS_EVENTS_TOTAL = Counter(f'{NAMESPACE}_suspicious_events_total', 'Security rules', ['rule_name'])
PROCESSING_DURATION_SECONDS = Histogram(f'{NAMESPACE}_processing_duration_seconds', 'Latency',
                                        buckets=(.001, .01, .1, 1.0))


# --- 3. Functions ---
def get_details(pkt):
    proto, sport, dport, version = "Other", "-", "-", "N/A"
    layer = None

    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        version = "v4" if pkt.haslayer(IP) else "v6"
        if pkt.haslayer(TCP):
            proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "icmp"
        elif pkt.haslayer(SCTP):
            proto, sport, dport = "sctp", pkt[SCTP].sport, pkt[SCTP].dport
    elif pkt.haslayer(ARP):
        layer = pkt[ARP]
        return layer.psrc, layer.pdst, f"arp_{'req' if layer.op == 1 else 'reply'}", layer.hwsrc, layer.hwdst, "L2"

    src_ip = getattr(layer, 'src', "-") if layer else "-"
    dst_ip = getattr(layer, 'dst', "-") if layer else "-"
    return src_ip, dst_ip, proto, sport, dport, version


def analyze_and_ingest(file_path, es_client):
    print(f"[*] Analyzing {file_path}...")
    if not os.path.exists(file_path):
        print(f"[-] Error: {file_path} not found.")
        return

    with PcapReader(file_path) as pcap_stream:
        for idx, pkt in enumerate(pcap_stream, start=1):
            with PROCESSING_DURATION_SECONDS.time():
                src, dst, proto, sport, dport, ip_ver = get_details(pkt)
                length = getattr(pkt, 'wirelen', len(pkt))

                PACKETS_TOTAL.labels(protocol=proto, version=ip_ver).inc()
                BYTES_TOTAL.labels(protocol=proto).inc(length)
                if dport in [22, 23, 3389, 445]:
                    SUSPICIOUS_EVENTS_TOTAL.labels(rule_name="mgmt_port_access").inc()

                doc = {
                    "@timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(),
                    "src_ip": src, "dst_ip": dst, "protocol": proto,
                    "length": length, "sport": str(sport), "dport": str(dport),
                    "ip_version": ip_ver, "packet_id": idx
                }

                try:
                    es_client.index(index=ELASTIC_INDEX, document=doc)
                    ELASTIC_INGESTION_TOTAL.labels(status="success").inc()
                except Exception as e:
                    ELASTIC_INGESTION_TOTAL.labels(status="failed").inc()
                    with open(FAILED_LOG, "a") as f:
                        f.write(json.dumps({"error": str(e), "doc": doc}) + "\n")


if __name__ == "__main__":
    start_http_server(METRICS_PORT)
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to PCAP")
    args = parser.parse_args()

    # Robust ES 8.x Connection
    es = Elasticsearch(
        ELASTIC_URL,
        verify_certs=False,
        request_timeout=30,
        retry_on_timeout=True
    )

    analyze_and_ingest(args.file, es)
    print("[*] Processing finished.")
    while True: time.sleep(10)