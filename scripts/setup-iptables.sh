#!/bin/bash
set -e

APIM_PE_IP="__APIM_PE_IP__"

# Enable IP forwarding now and persist it across reboots
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf \
    || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Idempotent DNAT rule: VMSS instance:443 -> APIM PE:443
iptables -t nat -C PREROUTING -p tcp --dport 443 -j DNAT \
    --to-destination "${APIM_PE_IP}:443" 2>/dev/null \
    || iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT \
       --to-destination "${APIM_PE_IP}:443"

# Ensure return path uses the VM instance source IP
iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -j MASQUERADE

echo '--- Current iptables NAT table ---'
iptables -t nat -L -n -v
