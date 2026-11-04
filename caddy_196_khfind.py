#!/usr/bin/env python3
"""Add /khfind/* -> fleet ingest (:8798) inside the api.reformboss.com site block."""
p = '/etc/caddy/Caddyfile'
lines = open(p).read().split('\n')
start = next((i for i, l in enumerate(lines) if l.strip().startswith('api.reformboss.com {')), None)
if start is None:
    print('api block not found')
    raise SystemExit(1)
end = next((j for j in range(start + 1, len(lines)) if lines[j] == '}'), None)
if end is None:
    print('block end not found')
    raise SystemExit(1)
if '/khfind/' in '\n'.join(lines[start:end]):
    print('already present')
    raise SystemExit
lines[end:end] = ['\thandle_path /khfind/* {', '\t\treverse_proxy 127.0.0.1:8798', '\t}']
open(p, 'w').write('\n'.join(lines))
print('inserted at line', end)