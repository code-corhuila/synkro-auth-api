# Initial administrator

Detailed procedures and delivery notes moved from the repository README at
[source cc45b66](https://github.com/code-corhuila/synkro-auth-api/blob/cc45b6634a40638445123bdcb62063a781249920/README.md).
Recorded execution results retain their original scope; moving them does not
constitute a new execution or certify a different revision.

Run commands from the repository root unless a step explicitly changes directory.

## Initial administrator

A new environment has nobody who can call `POST /api/v1/auth/register` (it needs an `ADMIN` token). The first
`ADMIN` is created by a dedicated command, `InitialAdminCli`, run once from a controlled deployment session. It is
**not** an endpoint, not a bypass of ordinary registration and not a recovery tool. It writes the user and an
`INITIAL_ADMIN_CREATED` record in `auth_schema.user_creation_audit` (actor kind `OPERATOR`, no actor user) in one
transaction.

### Who may run it, and when

Only the operator designated for the environment, from a deployment session whose access is already controlled,
**after the Auth migrations** (`synkro-auth-db` V014–V017 or later) and **before normal application traffic is
enabled**. The operator identity recorded in the audit (`--operator`, max 200 characters) is attribution of the
execution: free text proves nothing, so the authorization boundary is who can open that deployment session and read
the secrets it uses. Once the environment is initialized, remove routine access to the command (the image, the
secret files and the `auth_app` password) from everyone who does not need it.

### Run it

The command connects as `auth_app`, reading the same variables as the service (`SPRING_DATASOURCE_URL`,
`SPRING_DATASOURCE_USERNAME`, which must be `auth_app`, and `SPRING_DATASOURCE_PASSWORD_FILE` or
`SPRING_DATASOURCE_PASSWORD`). It never connects as the instance administrator and needs no JWT key. It builds its
own connection, starts no Spring context and opens no HTTP port. From the packaged artifact (in the image the jar is
`/app/auth-app.jar`):

```bash
export SPRING_DATASOURCE_URL='jdbc:postgresql://synkro-db:5432/synkro?currentSchema=auth_schema'
export SPRING_DATASOURCE_USERNAME=auth_app
export SPRING_DATASOURCE_PASSWORD_FILE=/run/secrets/auth_app_password
export SYNKRO_INIT_OPERATOR='deploy-pipeline@release-7'       # your deployment identity

java -cp auth-app.jar \
  -Dloader.main=co.edu.corhuila.synkro.auth.app.InitialAdminCli \
  org.springframework.boot.loader.launch.PropertiesLauncher \
  --name 'Initial Admin' --email 'admin@example.test' \
  --password-file /run/secrets/initial_admin_password
```

**From the service image.** The image's entrypoint starts the HTTP service, so the command replaces it
(`--entrypoint java`); the container runs as the image's non-root `synkro` user, the secret files are mounted
read-only and must be readable by that user, and the container must reach the database (here `--network`):

```bash
docker run --rm --network <network of the database> \
  -e SPRING_DATASOURCE_URL='jdbc:postgresql://synkro-db:5432/synkro?currentSchema=auth_schema' \
  -e SPRING_DATASOURCE_USERNAME=auth_app \
  -e SPRING_DATASOURCE_PASSWORD_FILE=/run/secrets/auth_app_password \
  -e SYNKRO_INIT_OPERATOR='deploy-pipeline@release-7' \
  -v /path/on/host/auth_app_password:/run/secrets/auth_app_password:ro \
  -v /path/on/host/initial_admin_password:/run/secrets/initial_admin_password:ro \
  --entrypoint java <service image> \
  -cp /app/auth-app.jar -Dloader.main=co.edu.corhuila.synkro.auth.app.InitialAdminCli \
  org.springframework.boot.loader.launch.PropertiesLauncher \
  --name 'Initial Admin' --email 'admin@example.test' --password-file /run/secrets/initial_admin_password
```

This exact form (image built from `deploy/Dockerfile`) was run against a disposable PostgreSQL with the real
`synkro-auth-db` migrations: the first run printed `result=created` (exit `0`), the second
`result=already_initialized` (exit `0`), both connected as `auth_app`. While the command waited for the lock, the
only socket its process held was the connection to PostgreSQL: there is no HTTP listener. The container's one
`LISTEN` row was Docker's embedded DNS resolver at `127.0.0.11`, which no process of the container owns. That
check is a manual observation, not an automated test (CI checks the host port instead, see the workflow).

| Input | Where | Notes |
|---|---|---|
| Name, email | `--name`, `--email` or `SYNKRO_INIT_ADMIN_NAME`, `SYNKRO_INIT_ADMIN_EMAIL` | Same rules as registration (name ≤ 150, valid email, normalized to lower case). |
| Password | `--password-file <file>` or `SYNKRO_INIT_ADMIN_PASSWORD_FILE`; otherwise a console prompt | 8–72 bytes. A file holds only the password (one trailing line break is ignored). Without a file the password is read twice **without echo**; with no console the command fails and asks for the file. It never falls back to an echoing reader, and **a password is never accepted as an argument** (`--password …` is refused without repeating it). |
| Operator | `--operator` or `SYNKRO_INIT_OPERATOR` | Required, 1–200 characters, no control characters. |
| Correlation id | `--correlation-id` or `SYNKRO_INIT_CORRELATION_ID` | Optional (≤ 128 characters); a UUID is generated otherwise. The same value appears in the output, the log line and the audit record. |

Do not put the password in the shell history, the process list or an example: write it to a deployment-managed secret
file with restrictive permissions. **The command never deletes that file.** Removing the temporary secret (and
confirming it is gone from the host, the volume and any CI workspace) is the operator's step after the run.

### Outcomes and exit codes

| Exit | Output | Meaning |
|---|---|---|
| `0` | `result=created`, `userId=…`, `correlationId=…` | The ADMIN and its audit record were committed. |
| `0` | `result=already_initialized`, `correlationId=…` | An ADMIN already exists, active or not. Nothing was written or changed: a successful no-op. |
| `1` | `error: unexpected failure (<type>)` | Anything else. Only the exception type is printed. |
| `2` | `error: …` per field | Invalid arguments, input or configuration, or the email belongs to another (non-ADMIN) user. Nothing was written. |
| `3` | `error: the initialization lock was not obtained within 10 seconds` | Another initialization, or a session, holds the lock. Nothing was written. |
| `4` | `error: the database failed … (SQLSTATE …)` | The database refused or lost the work before the commit. Nothing was kept. |
| `5` | `error: the outcome could not be confirmed` | The commit was sent but its confirmation never arrived. The ADMIN may or may not exist. |

Errors go to stderr and never contain the password, its hash, a connection URL or a driver message, only a SQLSTATE.
Each decision also writes one log line (`synkro.auth.initialization`: operation, outcome, operator, reason, UTC
timestamp, correlation id).

### What the transaction does

All steps share one connection (as `auth_app`) and one transaction:

1. begin an explicit `READ COMMITTED` transaction;
2. `SET LOCAL lock_timeout = '10s'`;
3. `SELECT pg_advisory_xact_lock(1398361682::bigint)`;
4. in a **separate statement**, check whether any user has role `ADMIN` (the `active` flag is ignored);
5. if one exists, commit without writing; otherwise insert the ADMIN (`active = true`, bcrypt hash) and its audit
   record, then commit.

The key `1398361682` is reserved for Auth's initial administrator creation within each environment's shared
PostgreSQL database; it is not derived from a schema, a string or a process, and no other code in that database
may take it. The lock is transaction-level, so a commit, a rollback or a lost connection releases it. The check is a
separate statement because, under `READ COMMITTED`, a statement that starts after the lock was granted sees what the
previous holder committed; fusing both into one statement would not. The ten seconds limit **waiting for the lock**,
not the whole command (connecting and hashing the password with bcrypt come on top).

### If it fails, or you are not sure

* **Exit 2**: fix the input or the configuration and run it again. Nothing was written.
* **Exit 3**: do not retry blindly. Check who holds the lock (`SELECT * FROM pg_locks WHERE locktype = 'advisory'
  AND objid = 1398361682`, joined to `pg_stat_activity` on `pid`) and whether an ADMIN already exists, then run it
  again as an explicit, authorized action. The command never retries by itself and never writes without the lock.
* **Exit 4**: nothing was kept. Fix the database or connection problem, then run it again.
* **Exit 5**: the outcome is unknown, so it is not reported as rolled back. Run the command again with the same
  settings: if the ADMIN was committed, it reports `already_initialized` (and nothing changes); otherwise it creates it.

### After the first run

1. Remove the temporary password file and restrict routine access to the command, as above.
2. Verify a normal login **through the gateway** with the new administrator (`POST /api/v1/auth/login`); a request
   straight to this service shows that the credentials work, not that the gateway routes them. Then register
   everyone else with `POST /api/v1/auth/register`.

### Limits

Initialization is not recovery. The check only sees users whose role is `ADMIN` right now: it cannot tell that an
`ADMIN` once existed and changed role, that every `ADMIN` was removed by an exceptional operation, or that the
environment was initialized before. The advisory lock is cooperative and is not a durable initialization marker, so
this procedure does not guarantee a single initialization for the life of the environment and does not authorize
running the command once normal operation has begun. A procedure to recover from losing every `ADMIN` is separate
work and is not implemented here. `scripts/create-local-user.sh` is local development tooling: it writes no audit
record and is not part of this procedure or evidence for it.
