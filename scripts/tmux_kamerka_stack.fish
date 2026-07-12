#!/usr/bin/env fish
# Start (or restart) a 4-pane tmux stack for Kamerka with Fish API keys.
# Attach: tmux attach -t kamerka

set -l root (path normalize (dirname (status filename))/..)
set -l session kamerka

tmux start-server 2>/dev/null

if tmux has-session -t $session 2>/dev/null
    echo "Session '$session' already exists — attach with: tmux attach -t $session"
    exit 0
end

tmux new-session -d -s $session -c $root -n stack
tmux split-window -h -t "$session:stack"
tmux select-pane -t "$session:stack.0"
tmux split-window -v -t "$session:stack.0"
tmux select-pane -t "$session:stack.2"
tmux split-window -v -t "$session:stack.2"
tmux select-layout -t "$session:stack" tiled

tmux select-pane -t "$session:stack.0" -T runserver
tmux select-pane -t "$session:stack.1" -T celery-worker
tmux select-pane -t "$session:stack.2" -T celery-beat
tmux select-pane -t "$session:stack.3" -T worker-status

tmux send-keys -t "$session:stack.0" "fish $root/scripts/kamerka.fish runserver" C-m
tmux send-keys -t "$session:stack.1" "fish $root/scripts/kamerka.fish worker" C-m
tmux send-keys -t "$session:stack.2" "fish $root/scripts/kamerka.fish celery beat --loglevel=info" C-m
tmux send-keys -t "$session:stack.3" \
    "fish -c \"while true; curl -sS -m 3 -H 'X-Requested-With: XMLHttpRequest' http://127.0.0.1:8000/api/worker_status 2>/dev/null | python3 -m json.tool; echo '---'; sleep 15; end\"" C-m

echo "Started tmux session '$session' (4 panes)."
echo "  tmux attach -t $session"