from elasticsearch import Elasticsearch

# Fix for 400 Errors: explicitly handle verify_certs
es = Elasticsearch("http://localhost:9200", verify_certs=False)
INDEX_NAME = "pcap_index"

def validate_index():
    try:
        if not es.indices.exists(index=INDEX_NAME):
            print(f"[-] Index {INDEX_NAME} not found.")
            return
        res = es.count(index=INDEX_NAME)
        print(f"[+] Total documents: {res['count']}")
        sample = es.search(index=INDEX_NAME, size=1)
        if sample['hits']['total']['value'] > 0:
            print("[+] Sample:", sample['hits']['hits'][0]['_source'])
    except Exception as e:
        print(f"[-] Validation Error: {e}")

if __name__ == "__main__":
    validate_index()