#!/usr/bin/env bash
# Start a 4-pane tmux stack for Kamerka. Attach: tmux attach -t kamerka
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
session=kamerka
command -v tmux >/dev/null || { echo "Install tmux first." >&2; exit 1; }
restart=false
if [[ "${1:-}" == --restart && $# -eq 1 ]]; then
    restart=true
elif [[ $# -gt 0 ]]; then
    echo "Usage: bash scripts/tmux_kamerka_stack.sh [--restart]" >&2
    exit 1
fi

if tmux has-session -t "$session" 2>/dev/null && ! "$restart"; then
    echo "Session '$session' already exists — attach with: tmux attach -t $session"
    echo "To replace a stale session: bash \"$root/scripts/tmux_kamerka_stack.sh\" --restart"
    exit 0
fi

if ! bash "$root/scripts/kamerka.sh" manage migrate --noinput; then
    echo "Database setup failed; tmux stack was not started. Check PostgreSQL and DB_* settings (see docs/INSTALL.md)." >&2
    exit 1
fi

if "$restart" && tmux has-session -t "$session" 2>/dev/null; then
    tmux kill-session -t "$session"
fi

server_pane="$(tmux new-session -d -s "$session" -c "$root" -n stack -x 160 -y 48 -P -F '#{pane_id}' 'bash --noprofile --norc')"
tmux set-option -w -t "$session:stack" remain-on-exit on
worker_pane="$(tmux split-window -h -t "$server_pane" -c "$root" -P -F '#{pane_id}' 'bash --noprofile --norc')"
beat_pane="$(tmux split-window -v -t "$server_pane" -c "$root" -P -F '#{pane_id}' 'bash --noprofile --norc')"
status_pane="$(tmux split-window -v -t "$worker_pane" -c "$root" -P -F '#{pane_id}' 'bash --noprofile --norc')"
tmux select-layout -t "$session:stack" tiled
tmux select-pane -t "$server_pane" -T runserver
tmux select-pane -t "$worker_pane" -T celery-worker
tmux select-pane -t "$beat_pane" -T celery-beat
tmux select-pane -t "$status_pane" -T worker-status

tmux respawn-pane -k -t "$server_pane" bash "$root/scripts/kamerka.sh" runserver
tmux respawn-pane -k -t "$worker_pane" bash "$root/scripts/kamerka.sh" worker
tmux respawn-pane -k -t "$beat_pane" bash "$root/scripts/kamerka.sh" celery beat --loglevel=info
tmux respawn-pane -k -t "$status_pane" bash -c \
    'while true; do curl -fsS -m 3 -H "X-Requested-With: XMLHttpRequest" http://127.0.0.1:8000/api/worker_status 2>/dev/null | python3 -m json.tool; echo ---; sleep 15; done'

echo "Started tmux session '$session' (4 panes)."
echo "  tmux attach -t $session"
echo "Failed processes remain visible in their panes; inspect their output after attaching."
