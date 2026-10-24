#!/bin/bash
# install-main.sh — PANOU + agent local pe netstreaming.eu (serverul principal)
# Folosire:  curl -fsSL https://raw.githubusercontent.com/maxvideostar/monitor/main/install-main.sh | bash
[ "$EUID" -eq 0 ] || { echo "Rulează ca root"; exit 1; }
REPO_RAW=https://raw.githubusercontent.com/maxvideostar/monitor/main
DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)
if [ -f "$DIR/nsmon.sh" ]; then cp -f "$DIR/nsmon.sh" /root/nsmon.sh
else curl -fsSL "$REPO_RAW/nsmon.sh" -o /root/nsmon.sh || { echo "Nu pot descărca nsmon.sh"; exit 1; }; fi
chmod +x /root/nsmon.sh
bash /root/nsmon.sh panel
