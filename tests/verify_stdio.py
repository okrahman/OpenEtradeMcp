"""Run after build: python3 tests/verify_stdio.py path/to/OpenEtradeMcp.Server.dll."""
import json
import os
import pathlib
import select
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="etrade-stdio-") as directory:
    root = pathlib.Path(directory).resolve()
    key = root / "key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    env = dict(os.environ, ETRADE_ConsumerKey="mock-consumer", ETRADE_ConsumerSecret="mock-secret",
               ETRADE_TokenDirectory=str(root / "tokens"), ETRADE_TokenKeyFile=str(key))
    process = subprocess.Popen([os.environ.get("DOTNET_HOST_PATH", "dotnet"), sys.argv[1]],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=env, text=True, bufsize=1)
    def request(identifier, method, params):
        process.stdin.write(json.dumps(dict(jsonrpc="2.0", id=identifier, method=method, params=params)) + "\n")
        process.stdin.flush()
        while True:
            assert select.select([process.stdout], [], [], 15)[0], "MCP response timed out"
            line = process.stdout.readline()
            assert line, "Server exited unexpectedly"
            response = json.loads(line)
            if response.get("id") == identifier:
                return response
    try:
        request(1, "initialize", dict(protocolVersion="2024-11-05", capabilities={}, clientInfo=dict(name="security-check", version="1")))
        process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        process.stdin.flush()
        response = request(2, "tools/list", {})
        names = {tool["name"] for tool in response["result"]["tools"]}
        forbidden = {"placeOrder", "cancelOrder", "placeChangeOrder"}
        assert not names & forbidden
        assert {"previewOrder", "previewChangeOrder", "listAccounts", "etrade_oauth_status"} <= names
        assert len(names) == 17
        for identifier, name in enumerate(sorted(forbidden), 3):
            response = request(identifier, "tools/call", dict(name=name, arguments={}))
            assert "error" in response or response.get("result", {}).get("isError"), response
        response = request(6, "tools/call", dict(name="etrade_oauth_status", arguments={}))
        assert not response["result"].get("isError", False)
        print("PASS: 17 tools discovered; all three trade invocations rejected; OAuth status works")
    finally:
        process.terminate()
        process.wait(timeout=10)
