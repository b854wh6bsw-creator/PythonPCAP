from elasticsearch import Elasticsearch
es = Elasticsearch("http://localhost:9200", verify_certs=False)

if es.ping():
    print("Simulator Ready!")
    doc = {"status": "testing"}
    res = es.index(index="check-index", document=doc, refresh=True)
    print(f"Verified: {es.get(index='check-index', id=res['_id'])['_source']}")