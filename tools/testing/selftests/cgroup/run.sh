#!/bin/sh
# These tests change global mount options and provoke a memcg OOM.
if [ "${MEMCG_TEST_ISOLATED:-}" != 1 ] ||
   [ -z "${MEMCG_TEST_DIR:-}" ]; then
    echo "TAP version 13"
    echo "1..0 # SKIP set isolated VM and page-cache directory variables"
    exit 0
fi
exec "$(dirname "$0")/memcg_protection" "$MEMCG_TEST_DIR"
