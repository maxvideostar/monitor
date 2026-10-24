#!/bin/bash
# install-s3.sh — agent nsmon pentru S3 — encoder (ffmpeg)
# Folosire:  curl -fsSL https://raw.githubusercontent.com/maxvideostar/monitor/main/install-s3.sh | bash -s <TOKEN> <IP_NETSTREAMING>
#  (TOKEN: pe netstreaming.eu rulează  bash /root/nsmon.sh token)
[ "$EUID" -eq 0 ] || { echo "Rulează ca root"; exit 1; }
NAME=s3
REPO_RAW=https://raw.githubusercontent.com/maxvideostar/monitor/main
TOKEN="$1"; PANEL="$2"
[ -z "$TOKEN" ] && read -rp "Token (bash /root/nsmon.sh token pe netstreaming.eu): " TOKEN </dev/tty
[ -z "$PANEL" ] && read -rp "IP public netstreaming.eu: " PANEL </dev/tty
[ -n "$TOKEN" ] && [ -n "$PANEL" ] || { echo "Token și IP obligatorii"; exit 1; }
DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd)
if [ -f "$DIR/nsmon.sh" ]; then cp -f "$DIR/nsmon.sh" /root/nsmon.sh
else curl -fsSL "$REPO_RAW/nsmon.sh" -o /root/nsmon.sh || { echo "Nu pot descărca nsmon.sh"; exit 1; }; fi
chmod +x /root/nsmon.sh
NSMON_NAME=$NAME bash /root/nsmon.sh agent "$TOKEN" "$PANEL"
