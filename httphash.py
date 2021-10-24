import sys
import hashlib
import requests

site = sys.argv[1]

print(hashlib.md5(requests.get(site, timeout=3).content).hexdigest())