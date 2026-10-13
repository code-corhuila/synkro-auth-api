#!/usr/bin/env bash
# Creates a user in auth_schema.system_user for LOCAL development.
#
# POST /api/v1/auth/register is now the normal way to create a user (it is public). This script
# remains for local convenience, e.g. to create an ADMIN without the API. It hashes the password
# with bcrypt on your machine and inserts the row as auth_app. Nothing is written to disk and no
# hash or password is committed anywhere. The email is lowercased, as the service does on register
# and on login, so the user can log in.
#
#   scripts/create-local-user.sh <email> <name> <ADMIN|SALESPERSON|INVENTORY>
#
# The password is read from the prompt, or from LOCAL_USER_PASSWORD when there is no terminal.
# Connection: the usual libpq variables (PGHOST, PGPORT, PGDATABASE, PGUSER=auth_app, PGPASSWORD).
# To reach a database inside a container, override the client:
#   PSQL="docker exec -i -e PGPASSWORD synkro-db psql -U auth_app -d synkro" scripts/create-local-user.sh ...
# bcrypt comes from `htpasswd` (apache2-utils) or, failing that, from the httpd:2.4-alpine image.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <email> <name> <ADMIN|SALESPERSON|INVENTORY>" >&2
  exit 2
fi
email=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
name=$2
role=$3
psql_cmd=${PSQL:-psql}

if [ -n "${LOCAL_USER_PASSWORD:-}" ]; then
  password=$LOCAL_USER_PASSWORD
else
  read -r -s -p "Password for $email: " password
  echo >&2
fi
if [ -z "$password" ]; then
  echo "The password cannot be empty." >&2
  exit 2
fi

bcrypt() {
  if command -v htpasswd >/dev/null 2>&1; then
    printf '%s' "$password" | htpasswd -niBC 10 user
  else
    printf '%s' "$password" | docker run --rm -i httpd:2.4-alpine htpasswd -niBC 10 user
  fi | cut -d: -f2 | tr -d '\r\n'
}
hash=$(bcrypt)
case "$hash" in
  '$2'*) ;;
  *) echo "Could not generate a bcrypt hash." >&2; exit 1 ;;
esac

# psql variables keep the hash out of the command line and out of shell history.
# shellcheck disable=SC2086  # PSQL may be a command with arguments
$psql_cmd -v ON_ERROR_STOP=1 -v name="$name" -v email="$email" -v role="$role" -v hash="$hash" <<'SQL'
INSERT INTO auth_schema.system_user (name, email, password_hash, role)
VALUES (:'name', :'email', :'hash', :'role');
SQL
echo "Created $role user $email" >&2
