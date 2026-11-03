#!/usr/bin/env bash
# HU-AUTH-15 verification fixture: an owned PostgreSQL + Auth + Gateway stack on its own network.
#
# Every Docker object this script creates is named auth15-* and carries the label synkro.task=auth-15, and every
# destructive command below addresses objects by those exact names. It never lists, prunes, stops or removes anything
# else, and it never touches the shared `platform` network or the synkro-dev project.
#
# Secrets (database passwords, the signing key, the first-administrator password) live in a private directory outside
# the repository, given by AUTH15_PRIVATE_DIR. They are generated here, never printed and never passed on a command line.
#
#   AUTH15_PRIVATE_DIR=/some/private/dir scripts/auth15/fixture.sh up       # database, schema, Auth, Gateway
#   AUTH15_PRIVATE_DIR=...               scripts/auth15/fixture.sh status
#   AUTH15_PRIVATE_DIR=...               scripts/auth15/fixture.sh down      # removes only the auth15-* objects
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

PRIV="${AUTH15_PRIVATE_DIR:?set AUTH15_PRIVATE_DIR to a private directory outside the repository}"
LABEL_KEY=synkro.task
LABEL_VALUE=auth-15
NET=auth15-net
VOL=auth15-pgdata
PG=auth15-pg
API=auth15-auth-api
GW=auth15-gateway
DB=synkro_auth_disposable_auth15
PG_IMAGE="${AUTH15_PG_IMAGE:-postgres:16.15-alpine3.23}"
FLYWAY_IMAGE="${AUTH15_FLYWAY_IMAGE:-flyway/flyway:11.20.3-alpine}"
HOST_PG_PORT="${AUTH15_PG_PORT:-15435}"
HOST_HTTP_PORT="${AUTH15_HTTP_PORT:-18085}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -W 2>/dev/null || pwd)"
REPO="$(cd "$HERE/../.." && { pwd -W 2>/dev/null || pwd; })"
WORKSPACE="${AUTH15_WORKSPACE:-$(cd "$REPO/.." && { pwd -W 2>/dev/null || pwd; })}"
AUTH_DB_REPO="${AUTH15_AUTH_DB_REPO:-$WORKSPACE/synkro-auth-db}"
GATEWAY_REPO="${AUTH15_GATEWAY_REPO:-$WORKSPACE/synkro-api-gateway}"
# Pinned like the CI job: a push to synkro-auth-db or synkro-api-gateway cannot change what this run proves.
AUTH_DB_REF="${AUTH15_AUTH_DB_REF:-c338bf95190fc20cbff55c13bb83c279a1febdf9}"
GATEWAY_REF="${AUTH15_GATEWAY_REF:-24a4ab1}"

# The Docker CLI wants a host path for a bind mount; Git Bash gives /c/... and Docker Desktop accepts C:/...
hostpath() { if command -v cygpath > /dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }

owned() { docker inspect -f "{{ index .Config.Labels \"$LABEL_KEY\" }}" "$1" 2> /dev/null | grep -qx "$LABEL_VALUE"; }

secret_file() { # name -> path, generated once
  local f="$PRIV/$1"
  if [ ! -s "$f" ]; then ( umask 077; openssl rand -hex 16 > "$f" ); fi
  printf '%s' "$f"
}

psql_admin() { # reads SQL on stdin
  docker exec -i "$PG" psql -U postgres -d "$DB" -v ON_ERROR_STOP=1 -q -tA "$@"
}

wait_pg() {
  for _ in $(seq 1 60); do
    if docker exec "$PG" pg_isready -U postgres -d "$DB" > /dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "error: $PG did not become ready" >&2; return 1
}

port_free() { ! netstat -ano 2> /dev/null | grep -E "[:.]$1[[:space:]]" | grep -q LISTENING; }

up_network_and_db() {
  mkdir -p "$PRIV"; chmod 700 "$PRIV" 2> /dev/null || true
  docker inspect "$PG" > /dev/null 2>&1 || port_free "$HOST_PG_PORT" || { echo "error: host port $HOST_PG_PORT is in use; not starting" >&2; exit 1; }
  docker inspect "$GW" > /dev/null 2>&1 || port_free "$HOST_HTTP_PORT" || { echo "error: host port $HOST_HTTP_PORT is in use; not starting" >&2; exit 1; }
  docker network inspect "$NET" > /dev/null 2>&1 || docker network create --label "$LABEL_KEY=$LABEL_VALUE" "$NET" > /dev/null
  docker volume inspect "$VOL" > /dev/null 2>&1 || docker volume create --label "$LABEL_KEY=$LABEL_VALUE" "$VOL" > /dev/null
  secret_file pg_admin_password > /dev/null
  secret_file auth_app_password > /dev/null
  printf 'POSTGRES_PASSWORD=%s\nPOSTGRES_DB=%s\n' "$(cat "$PRIV/pg_admin_password")" "$DB" > "$PRIV/pg.env"
  if docker inspect "$PG" > /dev/null 2>&1; then
    owned "$PG" || { echo "error: $PG exists but is not labelled $LABEL_KEY=$LABEL_VALUE; refusing" >&2; exit 1; }
    docker start "$PG" > /dev/null
  else
    docker run -d --name "$PG" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NET" --network-alias auth15-db \
      --env-file "$(hostpath "$PRIV/pg.env")" -v "$VOL:/var/lib/postgresql/data" \
      -p "127.0.0.1:$HOST_PG_PORT:5432" "$PG_IMAGE" > /dev/null
  fi
  wait_pg
}

create_login_role() {
  local pw; pw="$(cat "$PRIV/auth_app_password")"
  # Stands in for the bootstrap script of synkro-infra-postgres (ADR-012), exactly as the CI job does.
  psql_admin <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auth_app') THEN
    CREATE ROLE auth_app LOGIN PASSWORD '$pw';
  END IF;
END \$\$;
SQL
}

migrate_schema() {
  local src; src="$(mktemp -d)"
  git -C "$AUTH_DB_REPO" archive "$AUTH_DB_REF" | tar -x -C "$src"
  printf 'FLYWAY_URL=jdbc:postgresql://%s:5432/%s\nFLYWAY_USER=postgres\nFLYWAY_PASSWORD=%s\n' "$PG" "$DB" "$(cat "$PRIV/pg_admin_password")" > "$PRIV/flyway.env"
  local cid
  cid=$(docker create --label "$LABEL_KEY=$LABEL_VALUE" --network "$NET" --env-file "$(hostpath "$PRIV/flyway.env")" \
    "$FLYWAY_IMAGE" -workingDirectory=/workspace -configFiles=flyway.toml migrate)
  # copied in, not bind-mounted, exactly like the CI job
  docker cp -q "$(hostpath "$src")/." "$cid:/workspace"
  docker start -a "$cid" > /dev/null
  local code; code=$(docker inspect -f '{{.State.ExitCode}}' "$cid")
  docker rm -f "$cid" > /dev/null
  rm -rf "$src"
  [ "$code" = 0 ] || { echo "error: flyway exited $code" >&2; exit 1; }
  for table in system_user idempotency_key user_creation_audit; do
    [ "$(psql_admin -c "SELECT to_regclass('auth_schema.$table') IS NOT NULL;")" = t ] \
      || { echo "error: auth_schema.$table is missing" >&2; exit 1; }
  done
}

build_images() {
  local sha; sha="$(git -C "$REPO" rev-parse --short=12 HEAD)"
  docker build -q --label "$LABEL_KEY=$LABEL_VALUE" -t "auth15/synkro-auth-api:$sha" -f "$REPO/deploy/Dockerfile" "$REPO" > /dev/null
  local gsrc; gsrc="$(mktemp -d)"
  git -C "$GATEWAY_REPO" archive "$GATEWAY_REF" | tar -x -C "$gsrc"
  local gsha; gsha="$(git -C "$GATEWAY_REPO" rev-parse --short=12 "$GATEWAY_REF")"
  docker build -q --label "$LABEL_KEY=$LABEL_VALUE" -t "auth15/synkro-api-gateway:$gsha" -f "$(hostpath "$gsrc")/deploy/Dockerfile" "$(hostpath "$gsrc")" > /dev/null
  rm -rf "$gsrc"
  printf 'AUTH_IMAGE=auth15/synkro-auth-api:%s\nGATEWAY_IMAGE=auth15/synkro-api-gateway:%s\n' "$sha" "$gsha" > "$PRIV/images.env"
}

run_stack() {
  # shellcheck disable=SC1091
  . "$PRIV/images.env"
  [ -s "$PRIV/jwt-private.pem" ] || ( umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$(hostpath "$PRIV/jwt-private.pem")" ) || { echo "error: could not generate the signing key" >&2; exit 1; }
  for c in "$API" "$GW"; do
    if docker inspect "$c" > /dev/null 2>&1; then owned "$c" || { echo "error: $c is not ours" >&2; exit 1; }; docker rm -f "$c" > /dev/null; fi
  done
  docker run -d --name "$API" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NET" --network-alias synkro-auth-api \
    -e SERVER_PORT=8080 -e JWT_PRIVATE_KEY_FILE=/run/secrets/jwt_private_key \
    -e "SPRING_DATASOURCE_URL=jdbc:postgresql://$PG:5432/$DB?currentSchema=auth_schema" \
    -e SPRING_DATASOURCE_USERNAME=auth_app -e SPRING_DATASOURCE_PASSWORD_FILE=/run/secrets/auth_app_password \
    -v "$(hostpath "$PRIV/jwt-private.pem"):/run/secrets/jwt_private_key:ro" \
    -v "$(hostpath "$PRIV/auth_app_password"):/run/secrets/auth_app_password:ro" "$AUTH_IMAGE" > /dev/null
  docker run -d --name "$GW" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NET" \
    -e CORS_ALLOWED_ORIGINS=http://localhost:5173 -e RATE_LIMIT_PER_SECOND=50 \
    -p "127.0.0.1:$HOST_HTTP_PORT:8000" "$GATEWAY_IMAGE" > /dev/null
  for _ in $(seq 1 90); do
    if [ "$(docker exec "$API" wget -qO- http://127.0.0.1:8080/health 2> /dev/null | grep -c '"ok"')" -ge 1 ]; then return 0; fi
    sleep 1
  done
  echo "error: Auth did not report healthy" >&2; docker logs --tail 20 "$API" >&2 || true; return 1
}

initialize_admin() {
  # The real first-administrator path (HU-AUTH-14): the packaged CLI, run once as the operator, against the owned database.
  . "$PRIV/images.env"
  local out
  secret_file admin_password > /dev/null
  out=$(docker run --rm --label "$LABEL_KEY=$LABEL_VALUE" --network "$NET" \
    -e "SPRING_DATASOURCE_URL=jdbc:postgresql://$PG:5432/$DB?currentSchema=auth_schema" \
    -e SPRING_DATASOURCE_USERNAME=auth_app -e SPRING_DATASOURCE_PASSWORD_FILE=/run/secrets/auth_app_password \
    -e SYNKRO_INIT_OPERATOR=auth15-fixture -e SYNKRO_INIT_ADMIN_PASSWORD_FILE=/run/secrets/initial_admin_password \
    -v "$(hostpath "$PRIV/auth_app_password"):/run/secrets/auth_app_password:ro" \
    -v "$(hostpath "$PRIV/admin_password"):/run/secrets/initial_admin_password:ro" \
    --entrypoint java "$AUTH_IMAGE" -cp /app/auth-app.jar -Dloader.main=co.edu.corhuila.synkro.auth.app.InitialAdminCli \
    org.springframework.boot.loader.launch.PropertiesLauncher \
    --name 'AUTH15 Admin' --email 'auth15-admin@synkro.test' --correlation-id auth15-init-1)
  grep -E '^result=(created|already_initialized)$' <<< "$out"
}

case "${1:-}" in
  up)
    up_network_and_db
    create_login_role
    migrate_schema
    build_images
    run_stack
    initialize_admin
    echo "fixture up: gateway 127.0.0.1:$HOST_HTTP_PORT, postgres 127.0.0.1:$HOST_PG_PORT (database $DB)"
    ;;
  reset)
    # Owned disposable database only: the same identity proof the integration tests require before they empty auth_schema.
    docker inspect "$PG" > /dev/null 2>&1 && owned "$PG" || { echo "error: $PG is not ours" >&2; exit 1; }
    psql_admin --single-transaction <<SQL
DO \$\$ BEGIN
  IF current_database() <> '$DB' OR current_database() !~ '^synkro_auth_disposable_[a-z0-9_]+\$' THEN
    RAISE EXCEPTION 'refusing to empty auth_schema in database %', current_database();
  END IF;
END \$\$;
TRUNCATE auth_schema.user_creation_audit, auth_schema.refresh_token, auth_schema.service_token, auth_schema.idempotency_key, auth_schema.system_user CASCADE;
SQL
    initialize_admin
    ;;
  status)
    docker ps -a --filter "label=$LABEL_KEY=$LABEL_VALUE" --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
    ;;
  down)
    for c in "$GW" "$API" "$PG"; do
      if docker inspect "$c" > /dev/null 2>&1; then
        if owned "$c"; then docker rm -f "$c" > /dev/null; echo "removed $c"; else echo "skipped $c: not labelled ours" >&2; fi
      fi
    done
    if docker volume inspect "$VOL" > /dev/null 2>&1; then
      docker volume inspect -f "{{ index .Labels \"$LABEL_KEY\" }}" "$VOL" | grep -qx "$LABEL_VALUE" && docker volume rm "$VOL" > /dev/null && echo "removed $VOL"
    fi
    if docker network inspect "$NET" > /dev/null 2>&1; then
      docker network inspect -f "{{ index .Labels \"$LABEL_KEY\" }}" "$NET" | grep -qx "$LABEL_VALUE" && docker network rm "$NET" > /dev/null && echo "removed $NET"
    fi
    for img in $(docker images --filter "label=$LABEL_KEY=$LABEL_VALUE" --format '{{.Repository}}:{{.Tag}}'); do
      docker rmi "$img" > /dev/null && echo "removed image $img"
    done
    ;;
  *) echo "usage: AUTH15_PRIVATE_DIR=... $0 up|status|down" >&2; exit 2 ;;
esac
