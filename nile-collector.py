#!/usr/bin/env python3
"""
HTTP(S) Event Collector with Splunk Token Scheme, Nile SIEM Formatting,
Validation, Enrichment, Interface Binding, Debug Mode, SQLite Persistence,
Summary Option, Splunk HEC Endpoint Compatibility, Health Check,
CLI-Controlled Health-Check Log Suppression, Allow-Anything Mode,
and NDJSON Batch Support

Features:
- Token authentication using "Splunk <token>" (auto-generated if omitted)
- Nile SIEM schema validation & enrichment for known types
- Optional schema-less ingestion with -a/--allow-anything
- Supports root '/', '/events', and Splunk HEC '/services/collector/event'
- Health-check endpoint at '/services/collector/health'
- Suppress health-check & localhost access logs with -l/--suppress-health-logs
- Debug mode (-d) for verbose request logging
- Configurable interface (-i) and port (-p)
- Automatic or user-specified SQLite DB persistence (--db-file)
- Summary (-s) or detailed output
"""
import os
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
from flask import Flask, request, abort, jsonify
from dateutil import parser as dateparser

# Constants
SIOCGIFADDR = 0x8915
app = Flask(__name__)

# Globals
summary_mode = False
allow_anything = False
suppress_health_logs = False
token = None
db_conn = None

# Nile SIEM schema definitions
SCHEMA = {
    'audit_trail': [
        'version','id','auditTime','user','sourceIP','agent',
        'auditDescription','entity','action','eventType'
    ],
    'end_user_device_events': [
        'eventType','macAddress','ssid','bssid',
        'clientEventDescription','clientEventSeverity',
        'clientEventSuppressionStatus','timestamp','additionalDetails'
    ],
    'nile_alerts': [
        'version','id','alertSubscriptionCategory','alertType',
        'alertStatus','alertSubject','alertSummary','impact',
        'customer','site','building','floor','startTime',
        'duration','additionalInformation','eventType'
    ]
}

def get_ip_address(ifname):
    """Retrieve IPv4 address for the named interface."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        iface_bytes = struct.pack('256s', ifname.encode('utf-8')[:15])
        addr = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, iface_bytes)
        return socket.inet_ntoa(addr[20:24])
    except Exception as e:
        logging.error('Interface lookup failed for %s: %s', ifname, e)
        sys.exit(1)


def configure_logging(debug, suppress_health):
    """Configure root and werkzeug logging."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s %(levelname)s: %(message)s')
    app.debug = debug
    werk_logger = logging.getLogger('werkzeug')
    werk_logger.setLevel(level)
    if suppress_health:
        class AccessLogFilter(logging.Filter):
            def filter(self, record):
                msg = record.getMessage()
                if 'GET /services/collector/health' in msg:
                    return False
                if msg.startswith('127.0.0.1 - -'):
                    return False
                return True
        werk_logger.addFilter(AccessLogFilter())
    if debug:
        msg = 'Debug mode: verbose request logs'
        msg += '; health-check & localhost logs suppressed' if suppress_health else '; health-check & localhost logs enabled'
        logging.debug(msg)

@app.before_request

def log_request():
    """Log incoming requests when in debug mode, conditionally suppress health-check."""
    if app.debug:
        if suppress_health_logs and request.method == 'GET' and request.path == '/services/collector/health':
            return
        logging.debug('Request: %s %s', request.method, request.url)
        logging.debug('Headers: %s', dict(request.headers))
        logging.debug('Body: %s', request.get_data(as_text=True))

@app.errorhandler(404)

def handle_404(e):
    """Log and return 404 for unmatched routes."""
    logging.error('404 Not Found: %s %s', request.method, request.url)
    return 'Not Found', 404

# Health-check endpoint
@app.route('/services/collector/health', methods=['GET'])
def health_check():
    """Return HTTP 200 for valid health-check requests."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Splunk '):
        abort(401)
    if auth.split(' ',1)[1] != token:
        abort(401)
    return '', 200

# Event ingestion endpoints
@app.route('/', methods=['POST'])
@app.route('/events', methods=['POST'])
@app.route('/services/collector/event', methods=['POST'])
def receive_events():
    """Authenticate, parse JSON/NDJSON, optional validation, log, persist."""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Splunk '):
        logging.warning('Invalid auth scheme: %s', auth)
        abort(401)
    if auth.split(' ',1)[1] != token:
        logging.warning('Invalid token: %s', auth)
        abort(401)

    # Parse payload
    if request.is_json:
        data = request.get_json()
        if isinstance(data, dict) and 'event' in data and 'time' in data and 'sourcetype' in data:
            events = [data['event']]
        else:
            raw = data.get('events', data) if isinstance(data, dict) else data
            events = raw if isinstance(raw, list) else [raw]
    else:
        events = []
        for line in request.get_data(as_text=True).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logging.warning('Skipping invalid JSON line')
                continue
            if isinstance(obj, dict) and 'event' in obj and 'time' in obj and 'sourcetype' in obj:
                events.append(obj['event'])
            else:
                raw = obj.get('events', obj) if isinstance(obj, dict) else obj
                batch = raw if isinstance(raw, list) else [raw]
                events.extend(batch)

    now = int(time.time())
    for idx, ev in enumerate(events, 1):
        if not allow_anything:
            etype = ev.get('eventType')
            # Remap variant keys for end_user_device_events
            if etype == 'end_user_device_events' and all(
                k in ev for k in ('clientMac','clientEventTimestamp','clientEventAdditionalDetails')
            ):
                ev['macAddress'] = ev.pop('clientMac')
                ev['timestamp'] = ev.pop('clientEventTimestamp')
                ev['additionalDetails'] = ev.pop('clientEventAdditionalDetails')
                ev['ssid'] = ev.pop('connectedSsid', '')
                ev['bssid'] = ev.pop('connectedBssid', '')
                ev['clientEventSuppressionStatus'] = ev.get('clientEventSuppressionStatus', '')
            # Schema validation
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
                        dt = dateparser.parse(ev['auditTime'])
                        ev['auditTimeEpoch'] = int(dt.timestamp())
                    elif etype == 'nile_alerts':
                        st = dateparser.parse(ev['startTime'])
                        ev['startTimeEpoch'] = int(st.timestamp())
                    elif etype == 'end_user_device_events':
                        ts = ev['timestamp']
                        if isinstance(ts, str):
                            ev['timestamp'] = int(ts) if ts.isdigit() else int(dateparser.parse(ts).timestamp() * 1000)
                except Exception as e:
                    abort(400, description=f'Timestamp error for {etype}: {e}')
        # Log event
        payload = {'time': now, 'sourcetype': '_json', 'event': ev}
        if summary_mode:
            summary_map = {
                'audit_trail': {'id': ev.get('id'), 'user': ev.get('user'), 'action': ev.get('action'), 'time': ev.get('auditTimeEpoch')},
                'nile_alerts': {'id': ev.get('id'), 'type': ev.get('alertType'), 'subject': ev.get('alertSubject'), 'start': ev.get('startTimeEpoch')},
                'end_user_device_events': {'mac': ev.get('macAddress'), 'desc': ev.get('clientEventDescription'), 'time': ev.get('timestamp')}
            }
            logging.info('Summary [%d]: %s', idx, json.dumps(summary_map.get(ev.get('eventType'), {'eventType': ev.get('eventType')})))
        else:
            logging.info('Detailed [%d]: %s', idx, json.dumps(payload))

    # Persist events
    cursor = db_conn.cursor()
    for ev in events:
        cursor.execute(
            'INSERT INTO events(time,sourcetype,event) VALUES(?,?,?)',
            (now, '_json', json.dumps(ev))
        )
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
    parser.add_argument('-l', '--suppress-health-logs', action='store_true', help='Suppress health-check & localhost logs')
    parser.add_argument('-a', '--allow-anything', action='store_true', help='Allow any event format')
    parser.add_argument('--db-file', default='events.db', help='SQLite DB file (default: events.db)')
    parser.add_argument('-s', '--summary', action='store_true', help='Summary mode')
    args = parser.parse_args()

    # Apply flags
    summary_mode = args.summary
    allow_anything = args.allow_anything
    suppress_health_logs = args.suppress_health_logs
    configure_logging(args.debug, suppress_health_logs)

    # Determine bind address
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

