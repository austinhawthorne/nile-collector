#!/usr/bin/env python3
'''
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
  python event-collector.py -c cert.pem -k key.pem [options]

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
'''

import argparse
import json
import logging
import secrets
import socket
import struct
import fcntl
import time
import uuid
import sqlite3
import os
from flask import Flask, request, abort, jsonify
from dateutil import parser as dateparser

# Constants for interface ioctl
SIOCGIFADDR = 0x8915
app = Flask(__name__)
summary_mode = False
token = None
db_conn = None

# Nile SIEM schema definitions
SCHEMA = {
    'audit_trail': ['version','id','auditTime','user','sourceIP','agent','auditDescription','entity','action','eventType'],
    'end_user_device_events': ['eventType','macAddress','ssid','bssid','clientEventDescription','clientEventSeverity','clientEventSuppressionStatus','timestamp','additionalDetails'],
    'nile_alerts': ['version','id','alertSubscriptionCategory','alertType','alertStatus','alertSubject','alertSummary','impact','customer','site','building','floor','startTime','duration','additionalInformation','eventType']
}

def get_ip_address(ifname):
    '''Retrieve IPv4 address for interface.'''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        iface = struct.pack('256s', ifname.encode()[:15])
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, iface)
        return socket.inet_ntoa(res[20:24])
    except Exception as e:
        logging.error('Interface lookup failed for %s: %s', ifname, e)
        sys.exit(1)

def configure_logging(debug, suppress_health_logs=False):
    '''Configure logging for app and werkzeug.'''
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s: %(message)s')
    app.debug = debug
    # Configure Flask/Werkzeug access logs
    werk_logger = logging.getLogger('werkzeug')
    werk_logger.setLevel(level)
    if suppress_health_logs:
        class AccessLogFilter(logging.Filter):
            def filter(self, record):
                msg = record.getMessage()
                # Suppress health-check logs
                if 'GET /services/collector/health' in msg:
                    return False
                # Suppress local access logs from 127.0.0.1
                if msg.startswith('127.0.0.1 - -'):
                    return False
                return True
        werk_logger.addFilter(AccessLogFilter())
    if debug:
        msg = 'Debug mode: verbose request logs'
        if suppress_health_logs:
            msg += '; health-check & localhost logs suppressed'
        else:
            msg += '; health-check & localhost logs enabled'
        logging.debug(msg)

@app.before_request
def log_request():
    '''Log incoming requests when in debug mode.'''
    if app.debug:
        logging.debug('Request: %s %s', request.method, request.url)
        logging.debug('Headers: %s', dict(request.headers))
        logging.debug('Body: %s', request.get_data(as_text=True))

@app.errorhandler(404)
def handle_404(e):
    '''Log unmatched routes.'''
    logging.error('404 Not Found: %s %s', request.method, request.url)
    return 'Not Found', 404

# Health-check endpoint
@app.route('/services/collector/health', methods=['GET'])
def health_check():
    '''Return HTTP 200 for health checks.'''
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Splunk '):
        abort(401)
    if auth.split(' ',1)[1] != token:
        abort(401)
    return '', 200

# Event ingestion endpoints
@app.route('/events', methods=['POST'])
@app.route('/services/collector/event', methods=['POST'])
def receive_events():
    '''Authenticate, parse NDJSON or JSON batch, validate/enrich, log, persist.'''
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Splunk '):
        logging.warning('Invalid auth scheme: %s', auth)
        abort(401)
    if auth.split(' ',1)[1] != token:
        logging.warning('Invalid token: %s', auth)
        abort(401)

    raw_body = request.get_data(as_text=True)
    lines = raw_body.splitlines()
    all_events = []
    for line in lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            logging.warning('Skipping invalid JSON line')
            continue
        # Unwrap Splunk HEC envelope
        if isinstance(obj, dict) and 'event' in obj and 'time' in obj and 'sourcetype' in obj:
            events = [obj['event']]
        else:
            raw = obj.get('events', obj) if isinstance(obj, dict) else obj
            events = raw if isinstance(raw, list) else [raw]
        all_events.extend(events)

    now = int(time.time())
    for idx, ev in enumerate(all_events, 1):
        etype = ev.get('eventType')
        if etype in SCHEMA:
            missing = [f for f in SCHEMA[etype] if f not in ev]
            if missing:
                abort(400, description=f'Missing fields for {etype}: {missing}')
            if 'id' in ev:
                try:
                    uuid.UUID(ev['id'])
                except ValueError:
                    abort(400, description=f'Invalid UUID: {ev.get("id")}')
            try:
                if etype == 'audit_trail':
                    dt = dateparser.parse(ev['auditTime']); ev['auditTimeEpoch'] = int(dt.timestamp())
                elif etype == 'nile_alerts':
                    st = dateparser.parse(ev['startTime']); ev['startTimeEpoch'] = int(st.timestamp())
                elif etype == 'end_user_device_events':
                    ts = ev['timestamp']
                    if isinstance(ts, str):
                        ev['timestamp'] = int(ts) if ts.isdigit() else int(dateparser.parse(ts).timestamp() * 1000)
            except Exception as e:
                abort(400, description=f'Timestamp error for {etype}: {e}')
        else:
            logging.debug("Unknown eventType '%s'; skipping validation", etype)

        payload = {'time': now, 'sourcetype': '_json', 'event': ev}
        if summary_mode:
            summary_map = {
                'audit_trail': {'id': ev.get('id'), 'user': ev.get('user'), 'action': ev.get('action'), 'description': ev.get('auditDescription'), 'time': ev.get('auditTimeEpoch')},
                'nile_alerts': {'id': ev.get('id'), 'type': ev.get('alertType'), 'subject': ev.get('alertSubject'), 'summary': ev.get('alertSummary'), 'start': ev.get('startTimeEpoch')},
                'end_user_device_events': {'mac': ev.get('macAddress'), 'desc': ev.get('clientEventDescription'), 'time': ev.get('timestamp')}
            }
            logging.info('Summary [%d]: %s', idx, json.dumps(summary_map.get(etype, {'eventType': etype})))
        else:
            logging.info('Detailed [%d]: %s', idx, json.dumps(payload))

    # Persist all events
    cur = db_conn.cursor()
    for ev in all_events:
        cur.execute('INSERT INTO events(time,sourcetype,event) VALUES(?,?,?)', (now, '_json', json.dumps(ev)))
    db_conn.commit()

    return jsonify({"text": "Success", "code": 0}), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTP(S) Event Collector')
    parser.add_argument('-i', '--interface', help='Bind interface')
    parser.add_argument('-p', '--port', type=int, default=8088, help='Listen port')
    parser.add_argument('-t', '--token', help='Token; if omitted, Splunk token is generated')
    parser.add_argument('-c', '--certfile', help='SSL cert (for HTTPS)')
    parser.add_argument('-k', '--keyfile', help='SSL key (for HTTPS)')
    parser.add_argument('--http', action='store_true', help='Use plain HTTP')
    parser.add_argument('-d', '--debug', action='store_true', help='Verbose debug')
    parser.add_argument('-l', '--suppress-health-logs', action='store_true', help='Suppress health-check access logs')
    parser.add_argument('--db-file', default='events.db', help='SQLite DB file (default: events.db)')
    parser.add_argument('-s', '--summary', action='store_true', help='Summary mode')
    args = parser.parse_args()

    configure_logging(args.debug, args.suppress_health_logs)
    summary_mode = args.summary
    host = get_ip_address(args.interface) if args.interface else '0.0.0.0'

    # Initialize token and DB once (skip parent in debug mode)
    is_reloader = os.environ.get('WERKZEUG_RUN_MAIN') == 'true'
    if not args.debug or is_reloader:
        token = args.token if args.token else secrets.token_hex(16)
        logging.info('Token: %s', token)
        db_conn = sqlite3.connect(args.db_file, check_same_thread=False)
        c = db_conn.cursor()
        c.execute(
            'CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, time INTEGER, sourcetype TEXT, event JSON)'
        )
        db_conn.commit()
        logging.info('DB initialized at %s', args.db_file)

    # Start server
    if args.http:
        logging.info('Starting HTTP server at %s:%d', host, args.port)
        app.run(host=host, port=args.port, debug=args.debug)
    else:
        if not args.certfile or not args.keyfile:
            parser.error('certfile/keyfile required for HTTPS')
        logging.info('Starting HTTPS server at %s:%d', host, args.port)
        app.run(host=host, port=args.port, ssl_context=(args.certfile, args.keyfile), debug=args.debug)

