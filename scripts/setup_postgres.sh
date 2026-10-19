#!/usr/bin/env bash
# Provision a local application role/database without deleting existing data.
set -euo pipefail

db_user="${DB_USER:-kamerka}"
db_name="${DB_NAME:-kamerka}"
for command in psql createuser createdb; do
    command -v "$command" >/dev/null || {
        echo "Missing $command. Install PostgreSQL and start it first (see docs/INSTALL.md)." >&2
        exit 1
    }
done

admin=()
if ! psql -X --dbname postgres -c 'SELECT 1' >/dev/null 2>&1; then
    if [[ -z "${PREFIX:-}" ]] && command -v sudo >/dev/null; then
        admin=(sudo -u postgres)
    fi
    if ! "${admin[@]}" psql -X --dbname postgres -c 'SELECT 1' >/dev/null; then
        echo "Cannot connect as a local PostgreSQL administrator. Start PostgreSQL first (see docs/INSTALL.md)." >&2
        exit 1
    fi
fi

role_exists="$("${admin[@]}" psql -X --dbname postgres --set=ON_ERROR_STOP=1 --set=role="$db_user" -tA <<'SQL'
SELECT 1 FROM pg_roles WHERE rolname = :'role';
SQL
)"
if [[ "$role_exists" != 1 ]]; then
    echo "Creating PostgreSQL login '$db_user'. Enter the password you will use for DB_PASSWORD in .env."
    "${admin[@]}" createuser --login --pwprompt -- "$db_user"
else
    echo "Role '$db_user' already exists; its password and permissions were not changed."
fi

database_exists="$("${admin[@]}" psql -X --dbname postgres --set=ON_ERROR_STOP=1 --set=database="$db_name" -tA <<'SQL'
SELECT 1 FROM pg_database WHERE datname = :'database';
SQL
)"
if [[ "$database_exists" != 1 ]]; then
    "${admin[@]}" createdb --owner="$db_user" -- "$db_name"
else
    echo "Database '$db_name' already exists; it was not modified."
fi

echo "PostgreSQL role/database ready: DB_USER=$db_user DB_NAME=$db_name"
echo "Set matching DB_* values in .env, then run: bash scripts/kamerka.sh manage migrate --noinput"
