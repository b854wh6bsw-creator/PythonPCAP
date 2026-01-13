from elasticsearch import Elasticsearch

# Connect to the local simulator
es = Elasticsearch("http://localhost:9200")

# Check if the simulator is healthy
if es.ping():
    print("Simulator is ready for upload checks!")


# Upload document
doc = {"id": 1, "status": "testing"}
res = es.index(index="check-index", document=doc, refresh=True)

# Verification step
search_res = es.get(index="check-index", id=res['_id'])
print(f"Verified Document: {search_res['_source']}")
