import requests
import json
import time

KIB_URL = "http://localhost:5601/api/saved_objects/index-pattern/pcap-pattern"
headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
payload = {"attributes": {"title": "pcap_index", "timeFieldName": "@timestamp"}}

print("[*] Configuring Kibana index patterns...")
for _ in range(10):
    try:
        r = requests.post(KIB_URL, headers=headers, json=payload)
        if r.status_code == 200:
            print("[+] Success: Kibana is ready for searching.")
            break
    except:
        time.sleep(10)