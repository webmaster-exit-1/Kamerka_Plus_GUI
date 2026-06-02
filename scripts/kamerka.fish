#!/usr/bin/env fish
# Run Kamerka with API keys and tool paths from ~/.config/fish/config.fish.
#
# Usage:
#   fish scripts/kamerka.fish manage runserver 127.0.0.1:8000
#   fish scripts/kamerka.fish celery worker --loglevel=info
#   fish scripts/kamerka.fish test app_kamerka -v1
#   fish scripts/kamerka.fish runserver
#   fish scripts/kamerka.fish worker

if test -f "$HOME/.config/fish/config.fish"
    source "$HOME/.config/fish/config.fish" >/dev/null 2>&1
end

set -l root (path normalize (dirname (status filename))/..)
cd $root

set -l py "$root/venv/bin/python"
if not test -x $py
    echo "Missing venv: $py — run: python3 scripts/install_kamerka.py" >&2
    exit 1
end

if test (count $argv) -eq 0
    echo "Usage: fish scripts/kamerka.fish <command> [args...]"
    echo "  manage <django-args...>   — manage.py"
    echo "  celery <celery-args...>   — celery --app kamerka"
    echo "  test [pytest-args...]     — manage.py test"
    echo "  runserver [addr:port]     — Django dev server"
    echo "  worker                    — Celery worker"
    exit 1
end

set -l cmd $argv[1]
set -l rest $argv[2..]

switch $cmd
    case manage
        $py manage.py $rest
    case celery
        $py -m celery --app kamerka $rest
    case test
        $py manage.py test $rest
    case runserver
        if test (count $rest) -gt 0
            $py manage.py runserver $rest
        else
            $py manage.py runserver 127.0.0.1:8000
        end
    case worker
        $py -m celery --app kamerka worker --loglevel=info $rest
    case '*'
        echo "Unknown command: $cmd" >&2
        exit 1
end