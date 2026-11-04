#!/usr/bin/env python3
"""Insert full-access DashScope dorks at the top of the source queue.

A full key is one that serves qwen3.8-max / deepseek-v4-pro / glm-5.3, not just the
free omni model. Those keys appear where a project actually called a paid model, and
in intl workspace keys (sk-ws-...). Priority 1100+ keeps them ahead of everything else.
"""
import json
import sqlite3

DB = '/home/hermes/keyhunter-rs/data/scanner.db'
tasks = json.load(open('/root/dorks_ds_full.json'))
con = sqlite3.connect(DB, timeout=60)
added = upd = 0
for t in tasks:
    cur = con.execute('insert or ignore into source_tasks(source,query,priority) values(?,?,?)',
                      (t['source'], t['query'], t['priority']))
    if cur.rowcount:
        added += 1
    else:
        con.execute('update source_tasks set priority=?, enabled=1, cooldown_until=0 '
                    'where source=? and query=?', (t['priority'], t['source'], t['query']))
        upd += 1
con.commit()
act = con.execute('select count(*) from source_tasks where enabled=1').fetchone()[0]
top = con.execute('select priority,source,substr(query,1,44) from source_tasks '
                  'where enabled=1 order by priority desc limit 5').fetchall()
print('ds_full added=%d updated=%d active=%d' % (added, upd, act))
for p, s, q in top:
    print(' %5d %-7s %s' % (p, s, q))