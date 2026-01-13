import sys
import os
import json
import logging
import argparse
from datetime import datetime
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, SCTP
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError, ApiError

# --- Configuration ---
# In 2026, using environment variables is the standard for secure connection management
ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "pcap_index")
FAILED_LOG_FILE = "failed_ingestion.jsonl"

# Initialize Elasticsearch Client with built-in retry settings
es = Elasticsearch(
    ELASTIC_URL,
    retry_on_timeout=True,
    max_retries=3,
    retry_on_status=[429, 502, 503, 504]
)


def get_packet_details(pkt):
    """Extracts addresses, protocols, and ports for IP or ARP packets."""
    src_ip, dst_ip, proto, sport, dport = "-", "-", "Other", "-", "-"

    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        layer_l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP) or pkt.getlayer(SCTP)
        if layer_l4:
            proto = layer_l4.__class__.__name__
            sport, dport = layer_l4.sport, layer_l4.dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

    elif pkt.haslayer(ARP):
        arp = pkt[ARP]
        src_ip, dst_ip = arp.psrc, arp.pdst
        proto = f"ARP ({'Req' if arp.op == 1 else 'Reply'})"
        sport, dport = arp.hwsrc, arp.hwdst

    return src_ip, dst_ip, proto, sport, dport


def write_to_failed_log(data):
    """Writes failed packets to a local JSONL file for later recovery."""
    with open(FAILED_LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")


def index_packet(doc):
    """Attempts to write a single packet entry to Elasticsearch with manual retry logic."""
    try:
        es.index(index=ELASTIC_INDEX, document=doc)
    except (ConnectionError, ApiError) as e:
        # "Retry" Logic: One manual second attempt if the built-in client retries failed
        try:
            print(f"[!] Primary write failed, retrying once...")
            es.index(index=ELASTIC_INDEX, document=doc)
        except Exception:
            print(f"[CRITICAL] Retry failed. Logging to {FAILED_LOG_FILE}")
            write_to_failed_log(doc)


def analyze_and_ingest(file_path):
    print(f"[*] Starting ingestion for {file_path} into {ELASTIC_INDEX}...")

    try:
        with PcapReader(file_path) as pcap_stream:
            for idx, pkt in enumerate(pcap_stream, start=1):
                # 1. Extraction
                ts = datetime.fromtimestamp(float(pkt.time)).isoformat()
                length = getattr(pkt, 'wirelen', len(pkt))
                src, dst, proto, sport, dport = get_packet_details(pkt)

                # 2. Document Construction
                doc = {
                    "@timestamp": ts,
                    "packet_id": idx,
                    "src_ip": src,
                    "dst_ip": dst,
                    "protocol": proto,
                    "length": length,
                    "src_port": str(sport),
                    "dst_port": str(dport),
                    "file_source": os.path.basename(file_path)
                }

                # 3. Indexing
                index_packet(doc)

                if idx % 100 == 0:
                    print(f"Processed {idx} packets...")

    except Exception as e:
        print(f"Error reading PCAP: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PCAP to Elasticsearch Ingester")
    parser.add_argument("file", help="Input .pcap file")
    args = parser.parse_args()

    analyze_and_ingest(args.file)

