# nile-collector
Simple HTTP Event Collector to test integration with Nile

HTTP(s) Event Collector using Splunk's HTTP Event Collector API structure.  Allows for testing of Splunk integration with Nile before deploying a full Splunk solution.  Allows for analysis of different events, alerts, notifications from Nile and the schema that is used.

Features:
- Token authentication using "Splunk <token>" (auto-generated if omitted)
- Nile SIEM schema validation & enrichment for known types
- Supports Splunk HEC endpoints (/events, /services/collector/event)
- Health check endpoint (/services/collector/health) returning HTTP 200
- CLI option to suppress health-check access logs (-l/--suppress-health-logs)
- Interface binding by name
- Debug mode with verbose request logging and 404 diagnostics
- Always persists to SQLite DB (default: events.db)
- Summary or detailed output
- HTTP or HTTPS modes (HTTP mode will need something else terminating HTTPS and proxying the HTTP traffic to this collector)

Usage:
- First you need to do the below on the system that will be running this collector:
  - pip install flask python-dateutil
  - python nile-collector.py -c cert.pem -k key.pem [options]
    - You will need a valid certificate and this collector will have to be accessible via the Internet (how you accomplish this is outside the scope of this)
    - If you do not set a token, one will be generated, take note of it for the next step
- In a Nile tenant, setup a new Splunk integration using the URL/IPADDR of your collector instance (publicly accessible) and the token from the previous step.
- To test, run a test from the Nile tenant
- Events will be printed to the console and recorded in a db called events.db

Sample Output (Summary Mode):

- 2025-04-21 13:07:57,870 INFO: Summary [1]: {"eventType": "test"}
- 2025-04-21 13:30:02,084 INFO: Summary [1]: {"id": "046d0018-e2b2-48c3-9df2-b951e801d7f3", "user": "austin@nilesecurelab.net", "action": "Test", "description": "Tested SIEM 'default'", "time": 1745255278}
- 2025-04-21 13:30:02,087 INFO: Summary [2]: {"id": "bf3a7512-fbcd-4e41-9a5d-599d58ce2f01", "user": "austin@nilesecurelab.net", "action": "Login", "description": "Login Request", "time": 1745255188}
- 2025-04-21 13:30:02,090 INFO: Summary [3]: {"id": "fe594372-2f54-45fb-945b-d3ea2a99ef13", "user": "austin@nilesecurelab.net", "action": "Logout", "description": "Logout Request", "time": 1745254880}
- 2025-04-21 13:30:02,093 INFO: Summary [4]: {"id": "e87d470d-8850-400b-ab2b-b3919eaafa84", "user": "austin@nilesecurelab.net", "action": "Update", "description": "Updated DHCP Setting 'Acme-DHCP'", "time": 1745255237}
- 2025-04-21 13:30:02,095 INFO: Summary [5]: {"id": "bf53f3f5-01dd-44da-844b-661e46d72062", "user": "austin@nilesecurelab.net", "action": "Create", "description": "Created User 'Bob Jones'", "time": 1745255270}

Options:
- -i, --interface           Interface to bind to (e.g., eth0). Defaults to all.
- -p, --port                Port to listen on (default: 8088)
- -t, --token               Token for authentication; if omitted, a "Splunk" token is generated.
- -c, --certfile            SSL certificate file (required for HTTPS)
- -k, --keyfile             SSL key file (required for HTTPS)
- --http                    Run without TLS 
- -d, --debug               Enable debug mode (verbose request dump)
- -l, --suppress-health-logs  Suppress health-check access logs (off by default)
- --db-file                Path to SQLite DB file (default: events.db)
- -s, --summary             Print summarized events instead of full payloads

Notes:
- Have not tested HTTPS option, only HTTP at this point
- As this needs to be publicly accessible, care should be taken around the risk that this could bring to the host that is running this...for testing purposes only.
