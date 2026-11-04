#!/usr/bin/env python3
"""Add a /khfind/* route on hook.reformboss.com -> local ingest server :8799."""
p = '/etc/caddy/Caddyfile'
s = open(p).read()
if '/khfind/' in s:
    print('already present')
    raise SystemExit
anchor = '\thandle /health {\n\t\treverse_proxy 127.0.0.1:8811\n\t}\n'
if anchor not in s:
    print('anchor not found')
    raise SystemExit(1)
s = s.replace(anchor, '\thandle_path /khfind/* {\n\t\treverse_proxy 127.0.0.1:8799\n\t}\n' + anchor, 1)
open(p, 'w').write(s)
print('caddy patched')