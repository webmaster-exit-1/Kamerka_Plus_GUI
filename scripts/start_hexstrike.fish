#!/usr/bin/env fish
# Start HexStrike with PATH so health checks see ~/.local/bin and ~/go/bin shims.
set -l root (dirname (status dirname))
set -l hs $HOME/hexstrike-ai
if not test -d $hs
    echo "Missing $hs — clone hexstrike-ai first" >&2
    exit 1
end
if not test -x "$hs/venv/bin/python3"
    echo "Missing HexStrike virtual environment: $hs/venv/bin/python3" >&2
    echo "Run: cd $hs; python3 -m venv venv; venv/bin/pip install -r requirements.txt" >&2
    exit 1
end
set -gx PATH $HOME/.local/bin $HOME/go/bin /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin
cd $hs
exec $hs/venv/bin/python3 $hs/hexstrike_server.py $argv