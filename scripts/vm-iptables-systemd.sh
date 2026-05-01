#!/bin/bash
# =============================================================================
# vm-iptables-systemd.sh
#
# Configures iptables DNAT (port 443 -> APIM PE) and installs a systemd unit
# so rules survive reboots without requiring any packages (no internet needed).
#
# Usage:
#   chmod +x vm-iptables-systemd.sh
#   sudo ./vm-iptables-systemd.sh <APIM_PE_IP>
#
# Example:
#   sudo ./vm-iptables-systemd.sh 10.10.3.4
# =============================================================================
set -e

APIM_PE_IP="${1:?Usage: $0 <APIM_PE_IP>}"

# ---------------------------------------------------------------------------
# 1. Enable IP forwarding (persistent via sysctl.conf)
# ---------------------------------------------------------------------------
grep -q '^net.ipv4.ip_forward=1$' /etc/sysctl.conf \
    || echo 'net.ipv4.ip_forward=1' | tee -a /etc/sysctl.conf
sysctl -p

# ---------------------------------------------------------------------------
# 2. Apply iptables DNAT rules immediately (idempotent)
# ---------------------------------------------------------------------------
iptables -t nat -C PREROUTING -p tcp --dport 443 -j DNAT \
    --to-destination "${APIM_PE_IP}:443" 2>/dev/null \
    || iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT \
       --to-destination "${APIM_PE_IP}:443"

iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -j MASQUERADE

echo '--- Current iptables NAT table ---'
iptables -t nat -L -n -v

# ---------------------------------------------------------------------------
# 3. Install startup script
# ---------------------------------------------------------------------------
cat > /usr/local/bin/setup-iptables.sh << SCRIPT
#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -C PREROUTING -p tcp --dport 443 -j DNAT --to-destination ${APIM_PE_IP}:443 2>/dev/null || \\
    iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination ${APIM_PE_IP}:443
iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || \\
    iptables -t nat -A POSTROUTING -j MASQUERADE
SCRIPT

chmod +x /usr/local/bin/setup-iptables.sh

# ---------------------------------------------------------------------------
# 4. Install systemd unit (no package dependencies)
# ---------------------------------------------------------------------------
cat > /etc/systemd/system/iptables-dnat.service << UNIT
[Unit]
Description=iptables DNAT forwarder for APIM PE
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/setup-iptables.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable iptables-dnat.service
systemctl start  iptables-dnat.service
systemctl status iptables-dnat.service

echo 'Done. iptables DNAT rules are active and will persist across reboots.'
