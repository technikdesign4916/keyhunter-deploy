#!/usr/bin/env python3
"""Clean fix: all /khfind blocks out, one block into git.reformboss.com at site level."""
import re

p = '/etc/caddy/Caddyfile'
src = open(p).read()

# 1) strip every existing khfind block (3-line form)
cleaned, n = re.subn(r'\n\t?handle_path /khfind/\* \{\n[\t ]*reverse_proxy 127\.0\.0\.1:8799\n[\t ]*\}', '', src)
print('removed blocks:', n)
lines = cleaned.split('\n')

# 2) locate git site block and its closing brace at column 0
start = next(i for i, l in enumerate(lines) if l.startswith('git.reformboss.com'))
end = next(j for j in range(start + 1, len(lines)) if lines[j] == '}')
print('git block lines %d-%d' % (start, end))
lines[end:end] = ['\thandle_path /khfind/* {', '\t\treverse_proxy 127.0.0.1:8799', '\t}']
open(p, 'w').write('\n'.join(lines))
body = '\n'.join(lines[start:end + 4])
print('--- resulting git block ---')
print(body)