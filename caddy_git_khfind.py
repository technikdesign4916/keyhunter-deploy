#!/usr/bin/env python3
"""Route /khfind/* through git.reformboss.com (it resolves to this host) -> ingest :8799.

hook.reformboss.com has a Caddy block but no DNS record, so nodes cannot reach it.
"""
import re

p = '/etc/caddy/Caddyfile'
s = open(p).read()
if 'git.reformboss.com' not in s:
    print('no git block')
    raise SystemExit(1)
if '/khfind/' in s:
    print('already present')
    raise SystemExit

# insert right after the git.reformboss.com site block opener
m = re.search(r'(git\.reformboss\.com\s*\{[^\n]*\n)', s)
if not m:
    print('opener not found')
    raise SystemExit(1)
ins = '\thandle_path /khfind/* {\n\t\treverse_proxy 127.0.0.1:8799\n\t}\n'
s = s[:m.end()] + ins + s[m.end():]
open(p, 'w').write(s)
print('patched git.reformboss.com')