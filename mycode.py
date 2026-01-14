import os
import sys
import json
import time
import argparse
from datetime import datetime
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, SCTP
from elasticsearch import Elasticsearch
from prometheus_client import start_http_server, Counter, Gauge, Histogram

# --- Configuration & Environment ---
ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "pcap_index")
METRICS_PORT = int(os.getenv("ENV_METRICS_PORT", 9100))
FAILED_LOG = "failed_ingestion.jsonl"

# --- Prometheus Metrics Definition (2026 Standards) ---
PCAP_PACKETS = Counter('pcap_packets_total', 'Total packets processed', ['protocol'])
PCAP_BYTES = Counter('pcap_bytes_total', 'Total bytes on wire', ['protocol'])
ELASTIC_WRITE = Counter('pcap_elastic_write_total', 'Elasticsearch write status', ['status'])

# Creative Metrics for Thorough Analysis
SUSPICIOUS_TRAFFIC = Counter('pcap_suspicious_packets_total', 'Packets matching suspicious criteria', ['reason'])
IP_VERSION_COUNT = Counter('pcap_ip_version_total', 'Count of IPv4 vs IPv6', ['version'])
PROCESSING_TIME = Histogram('pcap_processing_seconds', 'Time spent processing packet batches')

# Initialize Elastic
es = Elasticsearch(ELASTIC_URL, retry_on_timeout=True, max_retries=2)


def get_details(pkt):
    """Extracts protocol, IPs, ports, and metadata."""
    proto, sport, dport, version = "Other", "-", "-", "N/A"
    layer = None  # Initialize to avoid UnboundLocalError

    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        version = "v4" if pkt.haslayer(IP) else "v6"

        # Transport Layer Extraction
        if pkt.haslayer(TCP):
            proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "icmp"
        elif pkt.haslayer(SCTP):
            proto, sport, dport = "sctp", pkt[SCTP].sport, pkt[SCTP].dport

    elif pkt.haslayer(ARP):
        proto, version = "arp", "L2"
        # ARP Opcode 1=Request, 2=Reply
        proto_detail = f"arp_{'req' if pkt[ARP].op == 1 else 'reply'}"
        return pkt[ARP].psrc, pkt[ARP].pdst, proto_detail, pkt[ARP].hwsrc, pkt[ARP].hwdst, version

    # Safe return: check if layer was actually assigned
    src_ip = getattr(layer, 'src', "-") if layer else "-"
    dst_ip = getattr(layer, 'dst', "-") if layer else "-"

    return src_ip, dst_ip, proto, sport, dport, version

def analyze_and_ingest(file_path):
    print(f"[*] Analyzing {file_path}...")

    with PcapReader(file_path) as pcap_stream:
        for idx, pkt in enumerate(pcap_stream, start=1):
            with PROCESSING_TIME.time():
                src, dst, proto, sport, dport, ip_ver = get_details(pkt)
                length = getattr(pkt, 'wirelen', len(pkt))

                # Update Prometheus Traffic Metrics
                PCAP_PACKETS.labels(protocol=proto).inc()
                PCAP_BYTES.labels(protocol=proto).inc(length)
                IP_VERSION_COUNT.labels(version=ip_ver).inc()

                # Creative Analysis: Flag common suspicious ports
                if dport in [22, 23, 3389]:
                    SUSPICIOUS_TRAFFIC.labels(reason="management_port_access").inc()

                # Document for Elastic
                doc = {
                    "@timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(),
                    "src_ip": src, "dst_ip": dst, "protocol": proto,
                    "length": length, "sport": str(sport), "dport": str(dport)
                }

                # Index to Elastic with Status Tracking
                try:
                    es.index(index=ELASTIC_INDEX, document=doc)
                    ELASTIC_WRITE.labels(status="success").inc()
                except Exception:
                    # Retry
                    try:
                        es.index(index=ELASTIC_INDEX, document=doc)
                        ELASTIC_WRITE.labels(status="success").inc()
                    except Exception:
                        ELASTIC_WRITE.labels(status="failed").inc()
                        with open(FAILED_LOG, "a") as f:
                            f.write(json.dumps(doc) + "\n")


if __name__ == "__main__":
    # 1. Start Prometheus Exporter
    start_http_server(METRICS_PORT)
    print(f"[*] Prometheus metrics at http://localhost:{METRICS_PORT}/metrics")

    # 2. Parse CLI
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()

    # 3. Execute
    analyze_and_ingest(args.file)

    print("[*] Finished. Metrics server active for scraping. Ctrl+C to stop.")
    while True: time.sleep(1)
