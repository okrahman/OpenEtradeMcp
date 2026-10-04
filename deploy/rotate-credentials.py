#!/usr/bin/env python3
"""Host-only approved Secret Manager replacement. Requires recent owner MFA approval.
Run on the VM through IAP. Approvals contain version numbers, never credentials.
"""
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import time
if os.geteuid()!=0:
    raise SystemExit('Host root required')
root=pathlib.Path('/srv/etrade/state')
secret_root=pathlib.Path('/run/etrade-secrets/gateway')
with sqlite3.connect(root/'authorization/authorization.db') as db:
    db.execute('BEGIN IMMEDIATE')
    row=db.execute('SELECT VersionsJson,ExpiresAt,Consumed,Action FROM MaintenanceApprovals WHERE Id=?',(sys.argv[1],)).fetchone()
    if not row or row[1]<=int(time.time()) or row[2] or row[3]!='credential_replacement':
        raise SystemExit('Owner approval is missing, expired or consumed')
    versions=json.loads(row[0])
    if set(versions)!= {'consumer-key','consumer-secret','token-key'} or any(not str(v).isdigit() or int(v)<=0 for v in versions.values()):
        raise SystemExit('Invalid approved versions')
    db.execute('UPDATE MaintenanceApprovals SET Consumed=1 WHERE Id=?',(sys.argv[1],))
    db.execute('UPDATE Grants SET Active=0')
    db.execute('INSERT INTO Audits(At,Action,Subject) VALUES(?,?,?)',(int(time.time()),'credential_replacement_started',sys.argv[1]))
    db.commit()
subprocess.run(['docker','compose','stop'],cwd='/opt/etrade/deploy',check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
# No fallback/start on retrieval failure. Approved versions are fetched through the host's narrow identity.
secret_map=json.load(open('/run/etrade-secret-map.json'))
project=sys.argv[2]
values={}
for filename,version in versions.items():
    identifier=secret_map['gateway/'+filename]
    result=subprocess.run(['gcloud','secrets','versions','access',str(version),'--secret',identifier,'--project',project],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    if filename=='token-key' and len(result.stdout)!=32 or filename!='token-key' and not result.stdout.strip():
        raise SystemExit('Invalid credential payload; services remain stopped')
    values[filename]=result.stdout
for filename,value in values.items():
    path=secret_root/filename
    temporary=path.with_suffix('.replacement')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as file:
        file.write(value);file.flush();os.fsync(file.fileno())
    os.chown(temporary,10001,10001);os.replace(temporary,path)
# Changed consumer/key state requires fresh authorization. Never copy or restore old tokens.
credentials=root/'gateway/credentials.json'
if credentials.exists():credentials.unlink()
for directory in (secret_root,root/'gateway'):
    fd=os.open(directory,os.O_RDONLY);os.fsync(fd);os.close(fd)
pin_path=pathlib.Path('/srv/etrade/brokerage-secret-versions.json')
pins=json.load(open(pin_path))
for filename,version in versions.items():pins['gateway/'+filename]=str(version)
with open(pin_path.with_suffix('.tmp'),'w') as file:
    os.chmod(file.name,0o600);json.dump(pins,file);file.flush();os.fsync(file.fileno())
os.replace(pin_path.with_suffix('.tmp'),pin_path)
print('Credentials replaced; all grants revoked. Recreate/start with firewall, then approve new isolated grants and fresh production authorization.')
