from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

# Fetch and print the 5 most recent packets
response = es.search(
    index="pcap_index",
    query={"match_all": {}},
    size=200,
    sort=[{"@timestamp": "desc"}]
)

for hit in response['hits']['hits']:
    print(hit['_source'])
