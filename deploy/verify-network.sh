#!/bin/bash
# Dedicated installation/CI fixture only; requires host root. Never probe Etrade write operations.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo 'Host root is required for firewall and namespace acceptance.' >&2; exit 1; }
repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"
if [ -f tests/.fixture-command.json ]; then
  mapfile -t compose_cmd < <(python3 -c 'import json;print("\n".join(json.load(open("tests/.fixture-command.json"))))')
else
  compose_cmd=(docker compose -f "$repo_root/deploy/compose.yaml" -f "$repo_root/deploy/compose.fixtures.yaml")
fi
"${compose_cmd[@]}" stop >/dev/null
"${compose_cmd[@]}" create >/dev/null
"$repo_root/deploy/firewall.sh"
"${compose_cmd[@]}" start >/dev/null
cleanup() { "${compose_cmd[@]}" stop >/dev/null; }
trap cleanup EXIT
sleep 5
probe() {
  local service=$1 mode=$2 host=$3 port=$4 identity pid
  identity=$("${compose_cmd[@]}" ps -q "$service")
  pid=$(docker inspect --format '{{.State.Pid}}' "$identity")
  nsenter --target "$pid" --net python3 "$repo_root/tests/network_probe.py" "$mode" "$host" "$port"
}
probe ingress allowed 172.30.10.3 8443
probe ingress allowed 172.30.11.3 8443
probe mcp allowed 172.30.12.3 8443
probe mcp allowed 172.30.13.3 8443
probe authorization allowed 172.30.14.3 8443
probe authorization allowed 172.30.16.3 3128
probe gateway allowed 172.30.14.2 8443
probe gateway allowed 172.30.15.3 3128
# Forbidden service directions, including same-bridge ports and transitive networks.
probe ingress denied 172.30.13.3 8443
probe mcp denied 172.30.15.3 3128
probe mcp denied 172.30.16.3 3128
probe authorization denied 172.30.15.3 3128
probe gateway denied 172.30.16.3 3128
probe gateway denied 172.30.10.3 8443
for service in ingress mcp authorization gateway; do
  probe "$service" denied 8.8.8.8 443
  probe "$service" denied 169.254.169.254 80
  probe "$service" denied 172.30.10.1 22
  probe "$service" denied 2001:4860:4860::8888 443
  probe "$service" dns-denied 8.8.8.8 53
done
printf '%s\n' 'PASS: allowed matrix, forbidden services, IP/IPv6, metadata, host service, external DNS and proxy bypass network probes'
