#!/usr/bin/env fish

# Start Kamerka Django + Celery worker + beat in background (Fish API keys).
set -l root (path normalize (dirname (status filename))/..)
set -l logdir "$root/logs"
mkdir -p $logdir

for pat in 'manage.py runserver' 'celery --app kamerka worker' 'celery --app kamerka beat'
    pkill -f $pat 2>/dev/null
end
sleep 1

set -l fish_script "$root/scripts/kamerka.fish"

echo "Starting runserver..."
nohup fish $fish_script runserver >>$logdir/runserver.log 2>&1 &
disown

echo "Starting celery worker..."
nohup fish $fish_script worker >>$logdir/celery-worker.log 2>&1 &
disown

echo "Starting celery beat..."
nohup fish $fish_script celery beat --loglevel=info >>$logdir/celery-beat.log 2>&1 &
disown

sleep 3
if curl -sS -m 5 -o /dev/null http://127.0.0.1:8000/
    echo "OK  http://127.0.0.1:8000/"
else
    echo "WARN runserver not responding yet — check $logdir/runserver.log"
end

if curl -sS -m 5 -H "X-Requested-With: XMLHttpRequest" http://127.0.0.1:8000/api/worker_status >/dev/null
    echo "OK  Celery worker API"
else
    echo "WARN worker API — check $logdir/celery-worker.log"
end

echo "Logs: $logdir/"