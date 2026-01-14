import requests
import json

KIBANA_URL = "http://localhost:5601/api/saved_objects/index-pattern/pcap-pattern"
headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
payload = {
    "attributes": {
        "title": "pcap_index",
        "timeFieldName": "@timestamp"
    }
}

try:
    response = requests.post(KIBANA_URL, headers=headers, data=json.dumps(payload))
    if response.status_code == 200:
        print("[+] Kibana Index Pattern created successfully!")
    else:
        print(f"[-] Failed: {response.text}")
except Exception as e:
    print(f"[-] Error: {e}")