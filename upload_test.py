from elasticsearch import Elasticsearch

es = Elasticsearch(
    "http://localhost:9200",
    meta_header=False,
    verify_certs=False
)

try:
    if es.ping():
        print("[+] Simulator ready!")
        doc = {"id": 1, "status": "testing"}
        res = es.index(index="check-index", document=doc, refresh=True)
        print(f"[+] Upload Success. ID: {res['_id']}")
except Exception as e:
    print(f"[-] Upload test failed: {e}")