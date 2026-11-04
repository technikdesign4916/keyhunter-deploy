#!/usr/bin/env python3
"""Audit injected channels for model substitution and dead quota.

A gateway that returns 200 but reports a different `model` in the body is serving its
own model under our name — worse than a 503, because the client silently gets the wrong
model. Same for gateways that answer 200 with a quota error inside.

Run on the iishko host. Reads channel ids/names/base_urls from PostgreSQL via psql.
"""
import json
import subprocess
import sys

PROBE = r'''
echo "select id,name,key,substr(base_url,1,70),substr(models,1,200) from channels where name like 'api-%' or name like 'xiaoai-%' or name like 'llm-%' or name like 'sabbir-%' order by id desc limit 12;" > /tmp/aud.sql
chmod 644 /tmp/aud.sql
su postgres -c 'psql -d newapi -At -F"|" -f /tmp/aud.sql'
'''


def rows():
    out = subprocess.run(['bash', '-lc', PROBE], capture_output=True, text=True, timeout=180).stdout
    res = []
    for line in out.splitlines():
        parts = line.split('|')
        if len(parts) >= 5 and parts[0].strip().isdigit():
            res.append({'id': parts[0], 'name': parts[1], 'key': parts[2],
                        'base': parts[3], 'models': parts[4].split(',')})
    return res


def probe(base, key, model):
    import requests
    url = base.rstrip('/') + '/chat/completions'
    try:
        r = requests.post(url, headers={'Authorization': 'Bearer ' + key},
                          json={'model': model, 'messages': [{'role': 'user', 'content': 'Reply with exactly: PONG'}],
                                'max_tokens': 12}, timeout=45)
    except Exception as e:
        return 'EXC %s' % type(e).__name__
    if r.status_code != 200:
        return 'HTTP%d %s' % (r.status_code, r.text[:70].replace('\n', ' '))
    try:
        j = r.json()
    except Exception:
        return 'NONJSON %s' % r.text[:60]
    if 'error' in j:
        return 'ERR ' + str(j['error'])[:80]
    served = str(j.get('model') or j.get('service') or '')
    content = ''
    try:
        content = j['choices'][0]['message'].get('content') or ''
    except Exception:
        pass
    return 'OK served=%s content=%s' % (served, content[:24].replace('\n', ' '))


def main():
    for r in rows():
        m = r['models'][0] if r['models'] else ''
        print('%-20s %-38s %-22s %s' % (r['name'][:20], r['base'][:38], m[:22],
                                        probe(r['base'], r['key'], m)), flush=True)


if __name__ == '__main__':
    main()