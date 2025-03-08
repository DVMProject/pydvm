# PyDVM

Python libraries for interacting with DVMProject applications

## DVMRest

`dvmrest.py` is used to interact with a DVM REST API endpoint, and handles authentication token exchange and automatic re-auth. `DVMRest` supports GET, PUT, and POST requests to DVM REST endpoints.

### Usage

```python
from .pydvm.dvmrest import DVMRest

# Create a new DVMRest connection
dvm_rest = DVMRest('127.0.0.1', 9990, 'PASSWORD)

# Query the list of peers from an FNE
rest_resp = dvm_rest.get("/peer/list")

# Iterate over the list of peers returned
for peer in rest_resp['peers']:
  print(peer)
```
