from elasticsearch import Elasticsearch
es = Elasticsearch("http://localhost:9200", verify_certs=False)

response = es.search(
    index="pcap_index",
    query={"match_all": {}},
    size=5,
    sort=[{"@timestamp": "desc"}]
)

for hit in response['hits']['hits']:
    print(hit['_source'])