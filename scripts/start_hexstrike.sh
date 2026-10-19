#!/usr/bin/env bash
# Start HexStrike with PATH so health checks see ~/.local/bin and ~/go/bin shims.
set -euo pipefail

hs="$HOME/hexstrike-ai"
if [[ ! -d "$hs" ]]; then
    echo "Missing $hs — clone hexstrike-ai first" >&2
    exit 1
fi
if [[ ! -x "$hs/venv/bin/python3" ]]; then
    echo "Missing HexStrike virtual environment: $hs/venv/bin/python3" >&2
    echo "Run: cd \"$hs\"; python3 -m venv venv; venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
cd -- "$hs"
exec "$hs/venv/bin/python3" "$hs/hexstrike_server.py" "$@"
