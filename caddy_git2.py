#!/usr/bin/env python3
"""Insert /khfind/* reverse proxy inside the git.reformboss.com site block.

git.reformboss.com resolves to this host, hook.reformboss.com has no DNS record and
port 8799 is firewalled, so this is the only public path for node ingest.
Line-based insertion: find the site block opener, insert before its closing brace.
"""
p = '/etc/caddy/Caddyfile'
lines = open(p).read().split('\n')
start = None
for i, l in enumerate(lines):
    if l.strip().startswith('git.reformboss.com'):
        start = i
        break
if start is None:
    print('git block not found')
    raise SystemExit(1)
end = None
for j in range(start + 1, len(lines)):
    if lines[j].strip() == '}':
        end = j
        break
if end is None:
    print('git block end not found')
    raise SystemExit(1)
body = '\n'.join(lines[start:end])
if '/khfind/' in body:
    print('already present in git block')
    raise SystemExit
ins = ['\thandle_path /khfind/* {', '\t\treverse_proxy 127.0.0.1:8799', '\t}']
lines[end:end] = ins
open(p, 'w').write('\n'.join(lines))
print('inserted into git block at line', end)