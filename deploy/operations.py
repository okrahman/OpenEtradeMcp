#!/usr/bin/env python3
"""Daily host-only approvals backup plus redacted audit export. Never copy brokerage tokens."""
import datetime
import json
import os
import pathlib
import sqlite3
root = pathlib.Path('/srv/etrade/state')
source = root / 'authorization/authorization.db'
if not source.exists():
    raise SystemExit('authorization storage missing')
now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
backup = root / 'approval-backups'
backup.mkdir(mode=0o700, exist_ok=True)
with sqlite3.connect(source) as db:
    # Export ONLY client/agent configuration; never OpenIddict tokens, nonces, cookies, TOTP secrets or recovery codes.
    data = {}
    for table in ('Clients', 'Grants'):
        cursor = db.execute('SELECT * FROM ' + table)
        names = [column[0] for column in cursor.description]
        data[table] = [dict(zip(names, row)) for row in cursor.fetchall()]
    path = backup / (datetime.datetime.date.today().isoformat() + '.json')
    temporary = path.with_suffix('.tmp')
    with open(temporary, 'w') as file:
        os.chmod(temporary, 0o600)
        json.dump(data, file)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)
    db.execute('DELETE FROM Audits WHERE At < ?', (now - 30*86400,))
    db.execute('DELETE FROM Nonces WHERE ExpiresAt <= ?', (now,))
    # Rebuild a bounded export; agent identifiers and fixed action names only.
    with open(root / 'redacted-audit.jsonl', 'w') as file:
        for at, action, subject in db.execute('SELECT At, Action, Subject FROM Audits ORDER BY Id'):
            file.write(json.dumps(dict(timestamp=at, action=action, subject=subject)) + '\n')
for path in backup.glob('*.json'):
    if path.stat().st_mtime < now - 7*86400:
        path.unlink()
