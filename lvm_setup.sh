#!/bin/bash
set -e
echo "=== LVM test setup ==="
LOOP1=$(sudo losetup -f --show /tmp/lvm-test1.img)
LOOP2=$(sudo losetup -f --show /tmp/lvm-test2.img)
echo "Loop devices: $LOOP1 $LOOP2"
sudo pvcreate "$LOOP1" "$LOOP2"
sudo vgcreate dsd_test_vg "$LOOP1" "$LOOP2"
sudo lvcreate -L 3G -T dsd_test_vg/thin_pool
sudo lvcreate -V 2G -T dsd_test_vg/thin_pool -n thin_vol
sudo lvcreate -s -L 256M -n snap_vol dsd_test_vg/thin_vol
echo "=== Done ==="
sudo vgs dsd_test_vg
sudo lvs dsd_test_vg
