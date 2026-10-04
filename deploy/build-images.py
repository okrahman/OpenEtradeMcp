#!/usr/bin/env python3
"""Build reviewed service images from pinned bases. Push/pin outputs explicitly during rollout."""
import json
import subprocess
import sys
pins = json.load(open('deploy/base-images.json'))
prefix = sys.argv[1] if len(sys.argv) > 1 else 'etrade-local'
for service in ('Server','Authorization','Gateway'):
    name = 'mcp' if service == 'Server' else service.lower()
    subprocess.run(['docker','build','-f','deploy/Dockerfile','--build-arg','SDK_IMAGE='+pins['sdk'],
        '--build-arg','RUNTIME_IMAGE='+pins['runtime'],'--build-arg','SERVICE='+service,'-t',prefix+'-'+name, '.'], check=True)
subprocess.run(['docker','build','-f','deploy/proxy/Dockerfile','--build-arg','PYTHON_IMAGE='+pins['python'],'-t',prefix+'-proxy','.'],check=True)
