import json
import sys

for name in sys.argv[1:]:
    with open(name) as f:
        json.load(f)
    print(f"ok {name}")
