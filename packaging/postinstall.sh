#!/bin/sh
# Refresh the systemd unit index so the installed services are visible.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi
exit 0
