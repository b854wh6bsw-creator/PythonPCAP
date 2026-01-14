from elasticsearch import Elasticsearch

# Use localhost for your Mac/PC terminal
es = Elasticsearch(
    "http://localhost:9200",
    meta_header=False,
    verify_certs=False
)

# FORCE THE HEADER MANUALLY
es.transport._accept_header = "application/vnd.elasticsearch+json; compatible-with=8"


def validate():
    try:
        res = es.info()
        print(f"[+] Success! Connected to cluster: {res['cluster_name']}")

        if es.indices.exists(index="pcap_index"):
            count = es.count(index="pcap_index")['count']
            print(f"[+] Total packets in index: {count}")
        else:
            print("[-] Index 'pcap_index' not found.")
    except Exception as e:
        print(f"[-] Connection failed despite force-compat: {e}")


if __name__ == "__main__":
    validate()