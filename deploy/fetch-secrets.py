#!/usr/bin/env python3
"""Narrow host-only retrieval: one explicit Secret Manager ID per owning service/file."""
import json
import os
import pathlib
import re
import subprocess
import sys
root = pathlib.Path('/run/etrade-secrets')
pin_path = pathlib.Path('/srv/etrade/brokerage-secret-versions.json')
pins = json.load(open(pin_path)) if pin_path.exists() else {}
root.mkdir(mode=0o711, exist_ok=True)
os.chmod(root, 0o711)
for destination, secret in json.load(open(sys.argv[1])).items():
    if not re.fullmatch(r'(ingress|mcp|authorization|gateway|brokerage-proxy|identity-proxy)/[a-zA-Z0-9._-]+', destination):
        raise ValueError('invalid destination')
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', secret):
        raise ValueError('invalid secret ID')
    path = root / destination
    path.parent.mkdir(mode=0o700, exist_ok=True)
    os.chown(path.parent, 10001, 10001)
    version = pins.get(destination, 'latest')
    if destination in ('gateway/consumer-key','gateway/consumer-secret','gateway/token-key') and version == 'latest':
        result = subprocess.run(['gcloud','secrets','versions','describe','latest','--secret',secret,'--project',sys.argv[2],'--format=value(name)'],check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        version = result.stdout.decode().strip().split('/')[-1]
        if not version.isdigit(): raise ValueError('invalid secret version')
        pins[destination] = version
    result = subprocess.run(['gcloud', 'secrets', 'versions', 'access', version, '--secret', secret, '--project', sys.argv[2]], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(result.stdout)
        file.flush()
        os.fsync(file.fileno())
    os.chown(path, 10001, 10001)

with open(pin_path.with_suffix('.tmp'),'w') as file:
    os.chmod(file.name,0o600)
    json.dump(pins,file);file.flush();os.fsync(file.fileno())
os.replace(pin_path.with_suffix('.tmp'),pin_path)
