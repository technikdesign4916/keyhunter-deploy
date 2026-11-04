#!/usr/bin/env python3
# Add request logging to the ingest handler so we can see what the nodes really send.
p = '/root/kh_ingest.py'
src = open(p).read()
if 'REQLOG' in src:
    print('already logging')
    raise SystemExit
marker = "    def log_message(self, fmt, *args):  # noqa: N802 - stdlib signature\n        pass"
probe = (
    "    def log_message(self, fmt, *args):  # noqa: N802 - stdlib signature\n"
    "        pass\n"
    "\n"
    "    def log_request(self, code='-', size='-'):  # REQLOG\n"
    "        try:\n"
    "            with open('/root/kh_ingest.log', 'a') as fh:\n"
    "                fh.write('%s %s %s %s %s\\n' % (\n"
    "                    __import__('time').strftime('%H:%M:%S'), self.command, self.path,\n"
    "                    code, (self.headers.get('User-Agent') or '-')[:40]))\n"
    "        except Exception:\n"
    "            pass"
)
if marker not in src:
    print('marker missing')
    raise SystemExit(1)
open(p, 'w').write(src.replace(marker, probe, 1))
print('logging added')