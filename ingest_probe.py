#!/usr/bin/env python3
"""Temporary probe: log every incoming method+path to see what nodes actually send."""
p = '/root/kh_ingest.py'
s = open(p).read()
if 'LOG_PROBE' not in s:
    s = s.replace(
        "    def log_message(self, fmt, *args):  # noqa: N802 - stdlib signature\n        pass",
        "    def log_message(self, fmt, *args):  # noqa: N802 - stdlib signature\n"
        "        pass\n\n"
        "    def log_request(self, code='-', size='-'):  # LOG_PROBE\n"
        "        try:\n"
        "            open('/root/kh_ingest.log', 'a').write(\n"
        "                '%s %s %s %s %s\\n' % (__import__('time').strftime('%H:%M:%S'),\n"
        "                                      self.command, self.path, code,\n"
        "                                      self.headers.get('User-Agent', '-')[:40]))\n"
        "        except Exception:\n"
        "            pass")
        open(p, 'w').write(s)
        print('probe added')
else:
    print('probe already present')