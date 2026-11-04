#!/usr/bin/env python3
"""Ingest endpoint: headless keyhunter nodes POST their findings here.

Nodes have ephemeral disks, so anything they find dies on restart. This keeps a
single central table (node_findings) fed by every node and deduped by (endpoint,key).
"""
import json
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = '/home/hermes/keyhunter-rs/data/scanner.db'
TOKEN_FILE = '/root/kh_ingest.token'
TOKEN = open(TOKEN_FILE).read().strip() if os.path.exists(TOKEN_FILE) else ''
LOCK = threading.Lock()


def db():
    con = sqlite3.connect(DB, timeout=30)
    con.execute(
        'create table if not exists node_findings('
        'id integer primary key autoincrement,'
        'node text, endpoint text, key text, status text, provider text,'
        'models_json text default \'\', chat_ok integer default 0,'
        'first_seen integer default (strftime(\'%s\',\'now\')),'
        'unique(endpoint, key))')
    con.execute('create index if not exists ix_node_findings_st on node_findings(status)')
    con.commit()
    return con


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: N802 - stdlib signature
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != '/find':
            self.send_response(404)
            self.end_headers()
            return
        if TOKEN and self.headers.get('X-Token') != TOKEN:
            self.send_response(401)
            self.end_headers()
            return
        try:
            n = int(self.headers.get('Content-Length') or 0)
            payload = json.loads(self.rfile.read(n) or b'[]')
        except Exception:
            self.send_response(400)
            self.end_headers()
            return
        rows = payload if isinstance(payload, list) else payload.get('rows', [])
        added = 0
        with LOCK:
            con = db()
            for r in rows[:500]:
                try:
                    cur = con.execute(
                        'insert or ignore into node_findings'
                        '(node,endpoint,key,status,provider,models_json,chat_ok) '
                        'values(?,?,?,?,?,?,?)',
                        (r.get('node', ''), r.get('endpoint', ''), r.get('key', ''),
                         r.get('status', ''), r.get('provider', ''),
                         json.dumps(r.get('models') or [])[:4000], 1 if r.get('chat_ok') else 0))
                    added += cur.rowcount
                except Exception:
                    pass
            con.commit()
            total = con.execute('select count(*) from node_findings').fetchone()[0]
            con.close()
        self._send(200, {'added': added, 'total': total})

    def do_GET(self):
        if self.path != '/stat':
            self.send_response(404)
            self.end_headers()
            return
        con = db()
        rows = con.execute('select status,count(*) from node_findings group by 1').fetchall()
        nodes = con.execute('select count(distinct node) from node_findings').fetchone()[0]
        con.close()
        self._send(200, {'by_status': dict(rows), 'nodes': nodes})


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8799), H).serve_forever()