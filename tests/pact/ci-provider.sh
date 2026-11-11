#!/usr/bin/env bash
# Real provider verification after Maven, inside the existing disposable integration job.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
database="synkro_auth_disposable_pact_$(openssl rand -hex 8)"
run_id="$(openssl rand -hex 12)"
scratch=$(mktemp -d)
chmod 700 "$scratch"
created=0
api_pid=''
runner="auth-pact-migrate-$run_id"
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n $api_pid ]] && jobs -pr | grep -qx "$api_pid"; then
    kill "$api_pid" || status=1
    for _ in $(seq 1 20); do jobs -pr | grep -qx "$api_pid" || break; sleep 1; done
    if jobs -pr | grep -qx "$api_pid"; then kill -KILL "$api_pid" || status=1; fi
    wait "$api_pid" 2>/dev/null || true
  fi
  if [[ $(docker inspect --format '{{index .Config.Labels "synkro.auth.pact"}}' "$runner" 2>/dev/null || true) == "$run_id" ]]; then docker rm -f "$runner" >/dev/null || status=1; fi
  if [[ $created == 1 ]]; then dropdb --if-exists "$database" || status=1; fi
  rm -f "$scratch"/admin-password "$scratch"/jwt.pem "$scratch"/flyway.env "$scratch"/api.log
  rmdir "$scratch" || status=1
  echo "Pact owned-resource cleanup finished (exit $status)"
  exit "$status"
}
trap cleanup EXIT
test "$(git -C "$root/synkro-auth-db" rev-parse HEAD)" = "$AUTH_DB_REF"
test -z "$(git -C "$root/synkro-auth-db" status --porcelain)"
[[ $database =~ ^synkro_auth_disposable_[a-z0-9_]+$ ]]
createdb "$database"
created=1
export PGDATABASE="$database"
export PACT_ADMIN_EMAIL="pact-admin@example.test"
PACT_ADMIN_PASSWORD=$(openssl rand -hex 24)
export PACT_ADMIN_PASSWORD
printf '%s' "$PACT_ADMIN_PASSWORD" >"$scratch/admin-password"
chmod 600 "$scratch/admin-password"
openssl genrsa -out "$scratch/jwt.pem" 2048 2>/dev/null
chmod 600 "$scratch/jwt.pem"
printf 'FLYWAY_URL=jdbc:postgresql://%s:%s/%s\nFLYWAY_USER=%s\nFLYWAY_PASSWORD=%s\n' "$PGHOST" "$PGPORT" "$database" "$PGUSER" "$PGPASSWORD" >"$scratch/flyway.env"
chmod 600 "$scratch/flyway.env"
docker create --name "$runner" --label "synkro.auth.pact=$run_id" --network host --env-file "$scratch/flyway.env" \
  "$FLYWAY_IMAGE" -workingDirectory=/workspace -configFiles=flyway.toml migrate >/dev/null
docker cp "$root/synkro-auth-db/." "$runner:/workspace"
docker start -a "$runner"
test "$(docker inspect --format '{{.State.ExitCode}}' "$runner")" = 0
export SPRING_DATASOURCE_URL="jdbc:postgresql://$PGHOST:$PGPORT/$database?currentSchema=auth_schema"
export SPRING_DATASOURCE_USERNAME=auth_app
export SPRING_DATASOURCE_PASSWORD="$AUTH_APP_PASSWORD"
export SYNKRO_INIT_OPERATOR="github-actions-pact/$run_id"
jar="$root/auth-app/target/auth-app-0.1.0-SNAPSHOT.jar"
java -cp "$jar" -Dloader.main=co.edu.corhuila.synkro.auth.app.InitialAdminCli org.springframework.boot.loader.launch.PropertiesLauncher \
  --name 'Pact Admin' --email "$PACT_ADMIN_EMAIL" --password-file "$scratch/admin-password"
# The CI VM is exclusive, and an existing listener is refused rather than replaced.
if ss -ltn | grep -q ':18081 '; then echo 'Pact provider port is already occupied' >&2; exit 1; fi
export JWT_PRIVATE_KEY_FILE="$scratch/jwt.pem" SERVER_PORT=18081
java -jar "$jar" >"$scratch/api.log" 2>&1 &
api_pid=$!
ready=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 http://127.0.0.1:18081/health >/dev/null 2>&1; then ready=1; break; fi
  kill -0 "$api_pid" 2>/dev/null || break
  sleep 1
done
test "$ready" = 1 || { echo 'Pact provider did not become healthy within its bounded startup wait' >&2; exit 1; }
export PROVIDER_BASE_URL=http://127.0.0.1:18081
node "$root/tests/pact/verify.mjs"
