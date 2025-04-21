# nile-collector
Simple HTTP Event Collector to test integration with Nile

HTTP(s) Event Collector using Splunk's HTTP Event Collector API structure.  Allows for testing of Splunk integration with Nile before deploying a full Splunk solution.  Allows for analysis of different events, alerts, notifications from Nile and the schema that is used.

Features:
- Token authentication using "Splunk <token>" (auto-generated if omitted)
- Nile SIEM schema validation & enrichment for known types
- Accepts unknown eventType values without schema validation
- Supports Splunk HEC endpoints (/events, /services/collector/event)
- Health check endpoint (/services/collector/health) returning HTTP 200
- CLI option to suppress health-check access logs (-l/--suppress-health-logs)
- Interface binding by name
- Debug mode with verbose request logging and 404 diagnostics
- Always persists to SQLite DB (default: events.db)
- Summary or detailed output
- HTTP or HTTPS modes

Usage:
- First you need to do the below on the system that will be running this collector:
  - pip install flask python-dateutil
  - python nile-collector.py -c cert.pem -k key.pem [options]
    - You will need a valid certificate and this collector will have to be accessible via the Internet (how you accomplish this is outside the scope of this)
    - If you do not set a token, one will be generated, take note of it for the next step
- In a Nile tenant, setup a new Splunk integration using the URL/IPADDR of your collector instance (publicly accessible) and the token from the previous step.
- To test, run a test from the Nile tenant
- Events will be printed to the console and recorded in a db called events.db

Options:
- -i, --interface           Interface to bind to (e.g., eth0). Defaults to all.
- -p, --port                Port to listen on (default: 8088)
- -t, --token               Token for authentication; if omitted, a "Splunk" token is generated.
- -c, --certfile            SSL certificate file (required for HTTPS)
- -k, --keyfile             SSL key file (required for HTTPS)
- --http                Run without TLS (plain HTTP)
- -d, --debug               Enable debug mode (verbose request dump)
- -l, --suppress-health-logs  Suppress health-check access logs (off by default)
- --db-file                Path to SQLite DB file (default: events.db)
- -s, --summary             Print summarized events instead of full payloads
