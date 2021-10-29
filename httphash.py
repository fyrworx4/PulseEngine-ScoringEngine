import sys
import hashlib
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

option = sys.argv[1]
site = sys.argv[2]

if option == "-https":
    print(hashlib.md5(requests.get(site, timeout=3, verify=False).content).hexdigest())
if option == "-http":
    print(hashlib.md5(requests.get(site, timeout=3).content).hexdigest())