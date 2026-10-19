#!/usr/bin/env bash
# Run Kamerka with configuration from .env or exported environment variables.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$root"
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"

py="$root/.venv/bin/python"
if [[ ! -x "$py" ]]; then
    py="$root/venv/bin/python"
fi
if [[ ! -x "$py" ]]; then
    echo "Missing Python environment: $root/.venv or $root/venv — run: python3 \"$root/scripts/install_kamerka.py\" --venv" >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "Usage: bash scripts/kamerka.sh <command> [args...]"
    echo "  manage <django-args...>   — manage.py"
    echo "  celery <celery-args...>   — celery --app kamerka"
    echo "  runserver [addr:port]     — Django dev server"
    echo "  worker                    — Celery worker"
    exit 1
fi

cmd="$1"
shift
args=("$@")
migration_options=()
for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[i]}" in
        --settings=*|--pythonpath=*)
            migration_options+=("${args[i]}")
            ;;
        --settings|--pythonpath)
            migration_options+=("${args[i]}")
            if ((i + 1 < ${#args[@]})); then
                i=$((i + 1))
                migration_options+=("${args[i]}")
            fi
            ;;
    esac
done
migration_args=()
if [[ "$cmd" == runserver || ( "$cmd" == manage && "${1:-}" == runserver ) ]]; then
    migration_args=(--noinput)
elif [[ "$cmd" == worker || ( "$cmd" == celery && ( "${1:-}" == worker || "${1:-}" == beat ) ) ]]; then
    migration_args=(--check)
fi

if [[ ${#migration_args[@]} -gt 0 ]]; then
    if ! "$py" manage.py "${migration_options[@]}" migrate "${migration_args[@]}"; then
        echo "Database setup failed. Check PostgreSQL and DB_* settings, then run: bash \"$root/scripts/kamerka.sh\" manage migrate --noinput" >&2
        exit 1
    fi
fi

case "$cmd" in
    manage)
        exec "$py" manage.py "$@"
        ;;
    celery)
        exec "$py" -m celery --app kamerka "$@"
        ;;
    runserver)
        if [[ $# -eq 0 ]]; then
            set -- 127.0.0.1:8000
        fi
        exec "$py" manage.py runserver "$@"
        ;;
    worker)
        exec "$py" -m celery --app kamerka worker --loglevel=info "$@"
        ;;
    *)
        echo "Unknown command: $cmd" >&2
        exit 1
        ;;
esac
