# nile-collector
Simple HTTP Event Collector to test integration with Nile

HTTP(S) Event Collector with Splunk Token Scheme, Nile SIEM Formatting,
Validation, Enrichment, Interface Binding, Debug Mode, SQLite Persistence,
Summary Option, Splunk HEC Endpoint Compatibility, Health Check,
Suppression of Health-Check Logs via CLI, and NDJSON Batch Support

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
  pip install flask python-dateutil
  python nile-collector.py -c cert.pem -k key.pem [options]

Options:
  -i, --interface           Interface to bind to (e.g., eth0). Defaults to all.
  -p, --port                Port to listen on (default: 8088)
  -t, --token               Token for authentication; if omitted, a "Splunk" token is generated.
  -c, --certfile            SSL certificate file (required for HTTPS)
  -k, --keyfile             SSL key file (required for HTTPS)
      --http                Run without TLS (plain HTTP)
  -d, --debug               Enable debug mode (verbose request dump)
  -l, --suppress-health-logs  Suppress health-check access logs (off by default)
  --db-file                Path to SQLite DB file (default: events.db)
  -s, --summary             Print summarized events instead of full payloads
