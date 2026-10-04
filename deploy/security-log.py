#!/usr/bin/env python3
import json
import sys
# Consume only fixed application events. Drop every other Docker log line.
for line in sys.stdin:
    try:
        event=json.loads(line)
        if set(event) == {'action'} and event['action'] in ('policy_denied','service_unavailable','reauthorization_required'):
            print(json.dumps(event), flush=True)
    except (ValueError, TypeError):
        pass
