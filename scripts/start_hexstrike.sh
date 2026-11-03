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
# Upstream hexstrike_server.py kills every tool at COMMAND_TIMEOUT = 300.
# Point that constant at HEXSTRIKE_COMMAND_TIMEOUT (default 30 min) once.
export HEXSTRIKE_COMMAND_TIMEOUT="${HEXSTRIKE_COMMAND_TIMEOUT:-1800}"
server="$hs/hexstrike_server.py"
if [[ -f "$server" ]]; then
    sed -i -E 's/^(COMMAND_TIMEOUT = )300([[:space:]]|$)/\1int(os.environ.get("HEXSTRIKE_COMMAND_TIMEOUT", "1800"))\2/' "$server"
fi
cd -- "$hs"
exec "$hs/venv/bin/python3" "$hs/hexstrike_server.py" "$@"
