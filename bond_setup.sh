#!/bin/bash
set -e
echo "=== Setting up bond0 via NetworkManager ==="

# Create bond
sudo nmcli connection add type bond ifname bond0 con-name bond0 \
  bond.options "mode=active-backup,miimon=100"

# Add slaves
sudo nmcli connection add type ethernet ifname eno1 con-name bond0-slave1 \
  master bond0

sudo nmcli connection add type ethernet ifname enp6s0f3u1 con-name bond0-slave2 \
  master bond0

# Bring up bond
sudo nmcli connection up bond0
sleep 3

echo "=== Bond status ==="
cat /proc/net/bonding/bond0 | grep -E "Bonding Mode|Currently Active Slave|MII Status|Speed" | head -8
ip addr show bond0 | grep -E "state|inet "
echo "=== dsd net ==="
sudo /usr/local/bin/dsd net --plain 2>&1 | head -20
