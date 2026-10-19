#!/usr/bin/env bash
# Start Kamerka Django + Celery worker + beat in the background.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
launcher="$root/scripts/kamerka.sh"

if ! bash "$launcher" manage migrate --noinput; then
    echo "Database setup failed; stack was not started. Check PostgreSQL and DB_* settings." >&2
    exit 1
fi

logdir="$root/logs"
mkdir -p -- "$logdir"
for pattern in 'manage.py runserver' 'celery --app kamerka worker' 'celery --app kamerka beat'; do
    pkill -f "$pattern" 2>/dev/null || true
done
sleep 1

echo "Starting runserver..."
nohup bash "$launcher" runserver >>"$logdir/runserver.log" 2>&1 &
echo "Starting celery worker..."
nohup bash "$launcher" worker >>"$logdir/celery-worker.log" 2>&1 &
echo "Starting celery beat..."
nohup bash "$launcher" celery beat --loglevel=info >>"$logdir/celery-beat.log" 2>&1 &

sleep 3
if curl -fsS -m 5 -o /dev/null http://127.0.0.1:8000/; then
    echo "OK  http://127.0.0.1:8000/"
else
    echo "WARN runserver not responding yet — check $logdir/runserver.log"
fi
if curl -fsS -m 5 -H "X-Requested-With: XMLHttpRequest" http://127.0.0.1:8000/api/worker_status >/dev/null; then
    echo "OK  Celery worker API"
else
    echo "WARN worker API — check $logdir/celery-worker.log"
fi
echo "Logs: $logdir/"
