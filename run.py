import os
import sys
from app import app

if os.environ.get("LAB_MODE", "1") != "1":
    print("Refusing to start: LAB_MODE must be 1 for this local training build.")
    sys.exit(1)

print("MY COLLECTIONS local pentest lab starting at http://127.0.0.1:5000")
print("Loopback-only. Do not expose this service to your LAN or the public internet.")
app.run(host="127.0.0.1", port=5000, debug=False)
