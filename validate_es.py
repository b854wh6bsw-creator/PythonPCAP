from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")
INDEX_NAME = "pcap_index"

def validate_index():
    # 1. Check if index exists
    if not es.indices.exists(index=INDEX_NAME):
        print(f"[-] Error: Index {INDEX_NAME} does not exist.")
        return

    # 2. Get document count
    res = es.count(index=INDEX_NAME)
    print(f"[+] Total documents in {INDEX_NAME}: {res['count']}")

    # 3. Verify a sample document
    sample = es.search(index=INDEX_NAME, size=1)
    if sample['hits']['total']['value'] > 0:
        print("[+] Sample Data Found:")
        print(sample['hits']['hits'][0]['_source'])
    else:
        print("[-] No documents found in the index.")

    # 4. Check Mapping (Schema)
    mapping = es.indices.get_mapping(index=INDEX_NAME)
    print("[+] Current Fields:", list(mapping[INDEX_NAME]['mappings']['properties'].keys()))

validate_index()
