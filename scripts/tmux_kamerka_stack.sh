#!/usr/bin/env bash
# Start a 4-pane tmux stack for Kamerka. Attach: tmux attach -t kamerka
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
session=kamerka
command -v tmux >/dev/null || { echo "Install tmux first." >&2; exit 1; }

if tmux has-session -t "$session" 2>/dev/null; then
    echo "Session '$session' already exists — attach with: tmux attach -t $session"
    exit 0
fi

if ! bash "$root/scripts/kamerka.sh" manage migrate --noinput; then
    echo "Database setup failed; tmux stack was not started. Check PostgreSQL and DB_* settings." >&2
    exit 1
fi

tmux new-session -d -s "$session" -c "$root" -n stack
tmux split-window -h -t "$session:stack" -c "$root"
tmux split-window -v -t "$session:stack.0" -c "$root"
tmux split-window -v -t "$session:stack.2" -c "$root"
tmux select-layout -t "$session:stack" tiled
tmux select-pane -t "$session:stack.0" -T runserver
tmux select-pane -t "$session:stack.1" -T celery-worker
tmux select-pane -t "$session:stack.2" -T celery-beat
tmux select-pane -t "$session:stack.3" -T worker-status

printf -v launcher '%q ' bash "$root/scripts/kamerka.sh"
tmux send-keys -t "$session:stack.0" "${launcher}runserver" C-m
tmux send-keys -t "$session:stack.1" "${launcher}worker" C-m
tmux send-keys -t "$session:stack.2" "${launcher}celery beat --loglevel=info" C-m
tmux send-keys -t "$session:stack.3" \
    "bash -c 'while true; do curl -fsS -m 3 -H \"X-Requested-With: XMLHttpRequest\" http://127.0.0.1:8000/api/worker_status 2>/dev/null | python3 -m json.tool; echo ---; sleep 15; done'" C-m

echo "Started tmux session '$session' (4 panes)."
echo "  tmux attach -t $session"
