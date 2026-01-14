from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200", meta_header=False, verify_certs=False)
es.transport._accept_header = "application/vnd.elasticsearch+json; compatible-with=8"

try:
    response = es.search(index="pcap_index", size=5, sort=[{"@timestamp": "desc"}])
    for hit in response['hits']['hits']:
        print(hit['_source'])
except Exception as e:
    print(f"[-] Viewer Error: {e}")