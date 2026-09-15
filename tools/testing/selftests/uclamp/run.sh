#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Use an existing CPU mount; the test creates and removes its own groups.
root=$(awk '$3 == "cgroup" && $4 ~ /(^|,)cpu(,|$)/ {print $2; exit}' /proc/mounts)
if [ -z "$root" ] || [ "$(id -u)" != 0 ]; then
    echo "TAP version 13"
    echo "1..0 # SKIP Requires root and a cgroup-v1 CPU mount"
    exit 4
fi
exec "$(dirname "$0")/uclamp" "$root"
