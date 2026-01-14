import os
import json
import time
import argparse
import logging
from datetime import datetime
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, ARP, SCTP
from elasticsearch import Elasticsearch
from prometheus_client import start_http_server, Counter, Histogram, Gauge

# ──────────────────────────────────────────────────────────────────────────────
# LOGGING SETUP - Console + File
# ──────────────────────────────────────────────────────────────────────────────

LOG_FILE = "pcap_ingestion.log"
FAILED_LOG = "failed_packets.jsonl"

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)
LOG_FILE = os.path.join("logs", LOG_FILE)
FAILED_LOG = os.path.join("logs", FAILED_LOG)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PCAP-Ingester")

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", "pcap_index")
METRICS_PORT = int(os.getenv("ENV_METRICS_PORT", 9100))

# ──────────────────────────────────────────────────────────────────────────────
# METRICS
# ──────────────────────────────────────────────────────────────────────────────

NAMESPACE = "pcap"
PACKETS_TOTAL = Counter(
    f'{NAMESPACE}_packets_total',
    'Total packets processed',
    ['protocol', 'version']
)
BYTES_TOTAL = Counter(
    f'{NAMESPACE}_bytes_total',
    'Total bytes processed',
    ['protocol']
)
ELASTIC_INGESTION_TOTAL = Counter(
    f'{NAMESPACE}_elastic_ingestions_total',
    'Elasticsearch ingestion attempts',
    ['status']
)
PROCESSING_DURATION = Histogram(
    f'{NAMESPACE}_packet_processing_seconds',
    'Packet processing duration',
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
)
LAST_SUCCESSFUL_PACKET = Gauge(
    f'{NAMESPACE}_last_successful_packet_id',
    'ID of the last successfully ingested packet'
)

# ──────────────────────────────────────────────────────────────────────────────
# PACKET PARSING
# ──────────────────────────────────────────────────────────────────────────────

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
        return layer.psrc, layer.pdst, f"arp_{'request' if layer.op == 1 else 'reply'}", "-", "-", "L2"

    src_ip = getattr(layer, 'src', "-") if layer else "-"
    dst_ip = getattr(layer, 'dst', "-") if layer else "-"

    return src_ip, dst_ip, proto, sport, dport, version


# ──────────────────────────────────────────────────────────────────────────────
# MAIN INGESTION LOGIC
# ──────────────────────────────────────────────────────────────────────────────

def analyze_and_ingest(file_path, es_client):
    if not os.path.exists(file_path):
        logger.error(f"PCAP file not found: {file_path}")
        return

    logger.info(f"Starting analysis of: {file_path}")
    logger.info(f"Elasticsearch target: {ELASTIC_URL}")
    logger.info(f"Target index: {ELASTIC_INDEX}")

    total_packets = 0
    success_count = 0
    failed_count = 0

    try:
        with PcapReader(file_path) as pcap_stream:
            for idx, pkt in enumerate(pcap_stream, start=1):
                total_packets = idx
                with PROCESSING_DURATION.time():
                    src, dst, proto, sport, dport, ip_ver = get_details(pkt)
                    length = len(pkt)

                    PACKETS_TOTAL.labels(protocol=proto, version=ip_ver).inc()
                    BYTES_TOTAL.labels(protocol=proto).inc(length)

                    doc = {
                        "@timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(),
                        "src_ip": src,
                        "dst_ip": dst,
                        "protocol": proto,
                        "length": length,
                        "sport": str(sport),
                        "dport": str(dport),
                        "ip_version": ip_ver,
                        "packet_id": idx
                    }

                    try:
                        response = es_client.index(index=ELASTIC_INDEX, document=doc)
                        success_count += 1
                        ELASTIC_INGESTION_TOTAL.labels(status="success").inc()
                        LAST_SUCCESSFUL_PACKET.set(idx)

                        if idx % 500 == 0:
                            logger.info(f"Progress: {idx} packets processed | "
                                        f"success: {success_count} | failed: {failed_count}")

                    except Exception as e:
                        failed_count += 1
                        ELASTIC_INGESTION_TOTAL.labels(status="failed").inc()

                        error_entry = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "packet_id": idx,
                            "error": str(e),
                            "document": doc,
                            "src_ip": src,
                            "dst_ip": dst,
                            "protocol": proto
                        }

                        # Write failed packet to persistent jsonl file
                        with open(FAILED_LOG, "a", encoding="utf-8") as f:
                            f.write(json.dumps(error_entry, ensure_ascii=False) + "\n")

                        logger.error(f"Failed to index packet #{idx} | "
                                     f"src={src} → dst={dst} ({proto}) | error: {e}")

    except KeyboardInterrupt:
        logger.warning("Ingestion interrupted by user")
    except Exception as e:
        logger.critical(f"Fatal error during processing: {e}", exc_info=True)
    finally:
        logger.info("──────────────────────────────────────────────")
        logger.info(f"FINISHED PROCESSING")
        logger.info(f"Total packets:     {total_packets}")
        logger.info(f"Successfully sent: {success_count}")
        logger.info(f"Failed:            {failed_count}")
        logger.info(f"Failed entries saved to: {FAILED_LOG}")
        logger.info(f"Full log available in: {LOG_FILE}")
        logger.info("──────────────────────────────────────────────")


if __name__ == "__main__":
    # Start Prometheus metrics server
    try:
        start_http_server(METRICS_PORT)
        logger.info(f"Prometheus metrics server started on port {METRICS_PORT}")
    except Exception as e:
        logger.critical(f"Failed to start metrics server on port {METRICS_PORT}: {e}")
        exit(1)

    # Parse arguments
    parser = argparse.ArgumentParser(description="PCAP → Elasticsearch Ingester")
    parser.add_argument("file", help="Path to .pcap file")
    args = parser.parse_args()

    # Elasticsearch client (compatible with ES 8.x)
    es = Elasticsearch(
        ELASTIC_URL,
        request_timeout=30,
        verify_certs=False
    )

    try:
        info = es.info()
        logger.info(f"Connected to Elasticsearch cluster: {info['cluster_name']}")
        logger.info(f"Elasticsearch version: {info['version']['number']}")

        analyze_and_ingest(args.file, es)

    except Exception as e:
        logger.critical(f"Failed to connect to Elasticsearch: {e}", exc_info=True)
        exit(1)

    logger.info("Ingestion finished. Metrics endpoint still active.")
    while True:
        time.sleep(30)