#!/bin/bash
# Run as root after Compose creates its bridges, BEFORE starting any containers.
# Tested with Docker's iptables backend; refuse nft-only mode or missing chains.
set -euo pipefail
modprobe br_netfilter
iptables -S DOCKER-USER >/dev/null
iptables -N ETRADE-BOUNDARY 2>/dev/null || true
iptables -F ETRADE-BOUNDARY
iptables -C DOCKER-USER -j ETRADE-BOUNDARY 2>/dev/null || iptables -I DOCKER-USER 1 -j ETRADE-BOUNDARY
iptables -A ETRADE-BOUNDARY -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
allow() { iptables -A ETRADE-BOUNDARY -s "$1" -d "$2" -p tcp --dport "$3" -j ACCEPT; }
allow 172.30.10.2 172.30.10.3 8443
allow 172.30.11.2 172.30.11.3 8443
allow 172.30.12.2 172.30.12.3 8443
allow 172.30.13.2 172.30.13.3 8443
allow 172.30.14.2 172.30.14.3 8443
# Gateway validates nonce consumption with authorization on their shared network.
allow 172.30.14.3 172.30.14.2 8443
allow 172.30.15.2 172.30.15.3 3128
allow 172.30.16.2 172.30.16.3 3128
# Public inbound reaches only ingress, only the TLS listener.
iptables -A ETRADE-BOUNDARY ! -s 172.30.0.0/16 -d 172.30.19.2 -p tcp --dport 8443 -j ACCEPT
# Reject internal/reserved destinations before allowing controlled proxy egress.
for source in 172.30.17.2 172.30.18.2; do
  for destination in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/3; do
    iptables -A ETRADE-BOUNDARY -s "$source" -d "$destination" -j DROP
  done
  iptables -A ETRADE-BOUNDARY -s "$source" -d 8.8.8.8 -p udp --dport 53 -j ACCEPT
  allow "$source" 8.8.8.8 53
  iptables -A ETRADE-BOUNDARY -s "$source" -p tcp --dport 443 -j ACCEPT
done
iptables -A ETRADE-BOUNDARY -s 172.30.0.0/16 -j DROP
iptables -A ETRADE-BOUNDARY -d 172.30.0.0/16 -j DROP
iptables -A ETRADE-BOUNDARY -j RETURN
# Docker forwarding must traverse host filtering even for same-bridge traffic.
sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.bridge.bridge-nf-call-ip6tables=1
# No container access to host sockets, metadata routes or host DNS forwarders.
iptables -C INPUT -s 172.30.0.0/16 -j DROP 2>/dev/null || iptables -I INPUT 1 -s 172.30.0.0/16 -j DROP
ip6tables -N ETRADE-V6 2>/dev/null || true
ip6tables -F ETRADE-V6
for bridge in $(docker network ls --filter label=com.docker.compose.project=etrade -q); do
  bridge_name="br-${bridge:0:12}"
  ip6tables -A ETRADE-V6 -i "$bridge_name" -j DROP
  ip6tables -C INPUT -i "$bridge_name" -j DROP 2>/dev/null || ip6tables -I INPUT 1 -i "$bridge_name" -j DROP
  ip6tables -A ETRADE-V6 -o "$bridge_name" -j DROP
done
ip6tables -C FORWARD -j ETRADE-V6 2>/dev/null || ip6tables -I FORWARD 1 -j ETRADE-V6
