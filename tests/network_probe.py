#!/usr/bin/env python3
"""Run with nsenter into a container's network namespace on a dedicated fixture host."""
import socket
import sys
mode,host,port=sys.argv[1:4]
port=int(port)
if mode=='dns-denied':
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(1)
    # A minimal standard A query; no credentials or financial data.
    sock.sendto(bytes.fromhex('123401000001000000000000')+b'\x07example\x03com\x00\x00\x01\x00\x01',(host,port))
    try:sock.recvfrom(512)
    except OSError:sys.exit(0)
    raise SystemExit('FAIL: external DNS responded')
sock=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET,socket.SOCK_STREAM)
sock.settimeout(1)
try:
    sock.connect((host,port))
    connected=True
except OSError:connected=False
finally:sock.close()
assert connected == (mode=='allowed'),(mode,host,port,connected)
