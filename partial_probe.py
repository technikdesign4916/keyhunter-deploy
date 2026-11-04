#!/usr/bin/env python3
"""Re-probe fleet PARTIAL rows with a model cascade.

A PARTIAL row means /models answered but the validator's chat probe failed — often
because the key only serves a different model. Running a cascade (dashscope models for
dashscope hosts, generic models otherwise) revives a real share of them.

Usage: partial_probe.py [limit] [workers]
Writes back status: VALID (chat 200 on >=1 model) or DEAD, and prints live keys.
"""
import concurrent.futures as cf
import json
import sqlite3
import sys

import requests

DB = '/root/kh_findings.db'
DS = ['deepseek-v4.1-flash-1017', 'qwen3.8-max', 'glm-5.3', 'qwen3.8-27b',
      'qwen3.5-omni-plus-2026-03-15']
GEN = ['gpt-4o-mini', 'gpt-5.6-terra', 'claude-fable-5-1', 'deepseek-v4.1-flash', 'grok-4.7']
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/156.0 Safari/537.36'


def looks_like_chat(resp):
    """A 200 from a random site means nothing: require a real chat completion body."""
    try:
        j = resp.json()
    except Exception:
        return False
    if not isinstance(j, dict):
        return False
    if 'choices' in j:
        return True
    if 'content' in j or 'result' in j or 'response' in j:
        return True
    err = str(j.get('error', '')).lower()
    return False


def probe(row):
    rid, ep, key = row
    base = ep.rstrip('/')
    models = DS if 'dashscope' in ep else GEN
    hits = []
    for m in models:
        try:
            r = requests.post(base + '/chat/completions',
                              headers={'Authorization': 'Bearer ' + key, 'User-Agent': UA},
                              json={'model': m, 'messages': [{'role': 'user', 'content': 'hi'}],
                                    'max_tokens': 3}, timeout=25)
            if r.status_code == 200 and looks_like_chat(r):
                hits.append(m)
                if len(hits) >= 3:
                    break
        except Exception:
            pass
    return rid, ep, key, hits


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 600
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 16
    con = sqlite3.connect(DB, timeout=60)
    rows = con.execute("select id,endpoint,key from node_findings "
                       "where upper(status)='PARTIAL' order by id limit ?", (limit,)).fetchall()
    print('probing %d PARTIAL rows' % len(rows), flush=True)
    live = 0
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for rid, ep, key, hits in ex.map(probe, rows):
            st = 'VALID' if hits else 'DEAD'
            con.execute('update node_findings set status=?, models_json=? where id=?',
                        (st, json.dumps(hits), rid))
            if hits:
                live += 1
                print('LIVE %-44s %-12s %s' % (ep[:44], key[:11], ','.join(hits)[:70]), flush=True)
    con.commit()
    print('done: live %d / %d' % (live, len(rows)))


if __name__ == '__main__':
    main()