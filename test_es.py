from elasticsearch import Elasticsearch

# Connect to the local simulator
es = Elasticsearch("http://localhost:9200")

# Check if the simulator is healthy
if es.ping():
    print("Simulator is ready for upload checks!")
