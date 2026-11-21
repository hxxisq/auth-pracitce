import base64
import json
from datetime import datetime

token = open("step0/token.txt").read().strip()
parts = token.split(".")
print(len(parts))

def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

header = json.loads(b64url_decode(parts[0]))   # JSON text -> dict
payload = json.loads(b64url_decode(parts[1]))  # JSON text -> dict
signature = b64url_decode(parts[2])            # raw bytes, not JSON

print(header)
print(payload)
print(signature)
print(len(signature))

print(datetime.fromtimestamp(payload["exp"]))  # read exp from the token