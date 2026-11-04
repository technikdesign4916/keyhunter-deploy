#!/usr/bin/env python3
"""Fix: /khfind route must sit at site-block level inside git.reformboss.com.

Previous run inserted it inside `handle /oauth/*` (first closing brace), where it is
unreachable. This removes the misplaced block and appends it before the block's own
closing brace (a `}` at column 0 after the opener).
"""
p = '/etc/caddy/Caddyfile'
lines = open(p).read().split('\n')

# 1) drop the misplaced 3-line block
out = []
i = 0
removed = 0
while i < len(lines):
    if lines[i].strip() == 'handle_path /khfind/* {' and removed == 0:
        i += 3
        removed += 1
        continue
    out.append(lines[i])
    i += 1
lines = out
print('removed misplaced block:', removed)

# 2) insert at the real end of the git site block
start = next(i for i, l in enumerate(lines) if l.strip().startswith('git.reformboss.com'))
end = None
for j in range(start + 1, len(lines)):
    if lines[j].rstrip() == '}':
        end = j
if end is None:
    print('no block end')
    raise SystemExit(1)
lines[end:end] = ['\thandle_path /khfind/* {', '\t\treverse_proxy 127.0.0.1:8799', '\t}']
open(p, 'w').write('\n'.join(lines))
print('inserted at site-block level, line', end)