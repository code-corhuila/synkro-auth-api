# synkro-auth-api

> auth bounded context: service API

Part of the **SynkroTech SAS Sales Management System** — organization `code-corhuila`.
Governance and documentation live in [`synkro-docs`](https://github.com/code-corhuila/synkro-docs).

## Branching

Three permanent branches. **None of them accepts a direct commit** — you enter through a child
branch and leave through a Pull Request.

```
develop  <--PR--  feat/... fix/... chore/...
qa       <--PR--  qa/...
main     <--PR--  release/...  hotfix/...
```

Promotion happens **by re-application** (`git cherry-pick -x`), never by merging one permanent
branch into another: `merge develop -> qa` and `merge qa -> main` do not exist in this model.

`main` requires **1 approval from `ariel5253`**. On `develop` and `qa` the team sets its own review
rule.

Full policy: `00-governance/branching-policy.md` in `synkro-docs`.

## Running locally

The service signs tokens with an RS256 private key and reads its users and refresh tokens from
PostgreSQL. It **refuses to start** without the key (`JWT_PRIVATE_KEY_FILE`) or without a usable
datasource (`SPRING_DATASOURCE_*`); see [Development](#development) for both.

```bash
export JWT_PRIVATE_KEY_FILE=/path/to/jwt-private.pem
export SPRING_DATASOURCE_URL='jdbc:postgresql://localhost:5432/synkro?currentSchema=auth_schema'
export SPRING_DATASOURCE_USERNAME=auth_app
export SPRING_DATASOURCE_PASSWORD='<the auth_app password of your local database>'
mvn install -DskipTests
mvn -pl auth-app spring-boot:run
```

The first command installs `auth-core` and `auth-adapters` into the local Maven repository so
`auth-app` can resolve them; re-run it after changing either module. The service listens on
`:8080`. Verify it:

```bash
curl http://localhost:8080/health
```

## Running the tests

```bash
mvn test
```

Unit and HTTP tests need no database. The `*IntegrationTest` classes run only when `TEST_DATABASE_URL`
is set, against a database whose schema was built from `synkro-auth-db`; they connect as `auth_app`
(`TEST_DATABASE_USER` overrides the user, `TEST_DATABASE_PASSWORD` is its password) and never delete
a row, so they can be re-run on the same database.

The one exception is the initial-administrator tests (`JdbcInitialAdminStoreIntegrationTest`,
`InitialAdminCliIntegrationTest`): initialization only happens on a database with no `ADMIN`, and `auth_app` cannot
delete, so each test first **empties `auth_schema`** through the instance administrator. That is destructive, so it
needs a throwaway database, an explicit opt-in and proof of which database it is:
`TEST_DATABASE_DISPOSABLE=true`, `TEST_ADMIN_DATABASE_PASSWORD` (`TEST_ADMIN_DATABASE_USER` defaults to `postgres`)
and `TEST_DISPOSABLE_DATABASE_NAME`. Consent and a password do not say *which* database answers, so before the
`TRUNCATE` the administrative connection asks the server `SELECT current_database()` and the answer must equal
`TEST_DISPOSABLE_DATABASE_NAME`, a name that must start with `synkro_auth_disposable_` (so `synkro`, `postgres` or
any shared name is refused). A missing or different name fails the test with an explanation, before anything is
emptied; the URL is not trusted for this. Without the three settings those tests **fail** rather than skip, and the
command under test still connects only as `auth_app`. Never point them at a shared or persistent database.

```bash
TEST_DATABASE_URL='jdbc:postgresql://localhost:5432/synkro_auth_disposable_local' TEST_DATABASE_PASSWORD='<auth_app password>' \
TEST_DATABASE_DISPOSABLE=true TEST_DISPOSABLE_DATABASE_NAME=synkro_auth_disposable_local \
TEST_ADMIN_DATABASE_PASSWORD='<admin password of the disposable database>' mvn -B verify
```

`mvn -B verify` also enforces the coverage thresholds of `11-quality/testing-strategy.md` with JaCoCo
(module `auth-coverage`): domain ≥ 90 %, application ≥ 80 % and global ≥ 80 % of lines on every run, and
infrastructure (the adapters) ≥ 60 % per package when `TEST_DATABASE_URL` is set. The report is written to
`auth-coverage/target/site/jacoco/index.html`.

## Development

### Signing key

`JWT_PRIVATE_KEY_FILE` must point to an unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`) holding an RSA
key of at least 2048 bits. Generate a throwaway one for local work and keep it out of git:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem   # what other services receive as JWT_PUBLIC_KEY
```

### Database

Users live in `auth_schema.system_user` and refresh tokens in `auth_schema.refresh_token`. The schema belongs
to [`synkro-auth-db`](https://github.com/code-corhuila/synkro-auth-db): **this service never runs migrations**
(no Flyway, no `schema.sql`). Build the schema there first, on an instance where the `auth_app` login exists
(`synkro-infra-postgres` creates it; `synkro-auth-db`'s README shows a throwaway stand-in for local work).

| Variable | Meaning |
|---|---|
| `SPRING_DATASOURCE_URL` | JDBC URL, `jdbc:postgresql://…?currentSchema=auth_schema`. Required. |
| `SPRING_DATASOURCE_USERNAME` | Must be `auth_app`. The service refuses to start as any other user (`auth_reader`, an administrator). |
| `SPRING_DATASOURCE_PASSWORD` or `SPRING_DATASOURCE_PASSWORD_FILE` | Exactly one. The file form is the one `deploy/compose.yml` uses (a mounted secret, like the signing key). |
| `SYNKRO_AUTH_REFRESH_TOKEN_TTL` | Optional, ISO-8601, default `P7D`. |

A missing or unusable value stops the startup with a message that names the variable and never prints the
password. The pool has 10 connections, a 5 s wait for one and a 5 s `statement_timeout`
(`05-architecture/cross-cutting.md` §8). The service starts without reaching the database; a request that
needs it while it is down answers `500 INTERNAL_ERROR` in the common error envelope, with no SQL, host or
credential in the body or in the log.

Rows are never deleted: `auth_app` has no `DELETE` privilege and no code path issues one. A refresh token is
stored as a SHA-256 hash with an `expiration_date` seven days ahead; rotating, logging out or revoking it marks the row
`active = false`. A user with `active = false` cannot log in, and gets the same `401` as a wrong password.

### The first local user

`synkro-auth-db` seeds no users, so a new local database has nobody to log in as, and `POST /api/v1/auth/register`
(see [Users](#users-register-and-lookup)) needs an `ADMIN` token. The first administrator therefore has to come from
outside the API. For a real environment that is the audited [initial administrator command](#initial-administrator).
For throwaway **local development only**, `scripts/create-local-user.sh` creates one directly in the database. It hashes
a password with bcrypt on your machine, lowercases the email like the service does, and inserts the row as `auth_app`;
it writes **no audit record**, so it does not implement the approved procedure and is no evidence for it. Log in as that
`ADMIN`, then register everyone else through the API. Nothing with a password or a hash is committed:

```bash
export PGHOST=localhost PGPORT=5432 PGDATABASE=synkro PGUSER=auth_app PGPASSWORD='<auth_app password>'
scripts/create-local-user.sh ana@example.test "Ana" ADMIN    # prompts for the password
```

Against a database inside a container, point `PSQL` at it:
`PSQL="docker exec -i -e PGPASSWORD synkro-db psql -U auth_app -d synkro" scripts/create-local-user.sh …`.
The bcrypt hash comes from `htpasswd` (apache2-utils) or, if it is not installed, from the `httpd:2.4-alpine` image.

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ana@example.test","password":"<the password you typed>"}'
# {"accessToken":"…","refreshToken":"…","tokenType":"Bearer","expiresIn":3600}

curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken from login>"}'
```

A refresh token works once: using it returns a new pair and invalidates the old token. Replaying it is a `401` and revokes every refresh token of that user (see [Sessions](#sessions-logout-and-refresh-token-reuse)).

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

## Users: register and lookup

| Endpoint | Who | Success |
|---|---|---|
| `POST /api/v1/auth/register` | A human `ADMIN` with a valid access token, decided in `RegisterUserUseCase` itself; it creates `ADMIN`, `SALESPERSON` or `INVENTORY` users | `201` + `Location: /api/v1/auth/users/{id}`, or `200` on a replay; body `UserResponse` |
| `GET /api/v1/auth/users/{id}` | `ADMIN` only, decided in `GetUserUseCase` with `RoleGuard` | `200` `UserResponse` |

`UserResponse` is `{ userId, name, email, role, registrationDate, active }`. The password and its hash are never
returned. `register` takes `{ name (1–150), email (3–255, valid), password (8–72 bytes), role }`; `SERVICE` or any
other role is rejected before the database is touched. The 72-byte ceiling is bcrypt's own limit: a longer
password would be silently truncated.

**Headers.** `Idempotency-Key` (8–128 characters) is **required** on `register`; a missing or out-of-range key is a
`400 VALIDATION_ERROR`. `X-Correlation-Id` is reused if sent, generated otherwise, echoed in every response and used
as the `traceId` of every error. `Authorization: Bearer …` is needed on both `register` and the lookup.

**Who may register, and why.** Registration requires authentication because an unauthenticated caller must not be
able to create or discover accounts, and it requires an `ADMIN` because creating an employee account is an
administrative act that has to be attributable to a person. The use case receives the verified caller from the HTTP
adapter (the token's claims, never the body or an `X-User-*` header) and refuses it itself, so the rule holds when the
use case is called without the HTTP layer or a gateway in front of it:

- no valid token: `401`; a `SALESPERSON` or `INVENTORY` token: `403`;
- a human token (any role other than `SERVICE`) whose `sub` is not a UUID in its canonical form (36 characters,
  with dashes) is not a valid identity: `401`, on every protected route. A human is identified by a user id, so the
  HTTP adapter, which owns authentication, refuses anything else before a use case runs. Login and refresh stay
  public, and an invalid `Authorization` header on them is still ignored. A `SERVICE` token is identified by its
  service name and is not held to that rule;
- a well-formed `ADMIN` token whose user does not exist is `403` with a generic message, decided in the use case
  before the request is validated and before the key or the email is read: a token alone does not prove that the
  account is there, and a refusal must not reveal what the key produced. A database that cannot answer that lookup
  is a `500`, never a `403`: an unreachable store is not an absent administrator. The identity and the role still
  come from the validated token, so this check does not revoke anything: a deactivated or demoted administrator
  keeps working until the token expires, and that policy is not changed here;
- a `SERVICE` token is always `403`, even for an `Idempotency-Key` that already created a user;
- authorization is decided **before** the request is validated and **before** the idempotency key is looked up, so a
  refused caller cannot learn whether a key already produced a user: a refused replay gets the same `403` as a first attempt.

**Idempotency.** The user, its `idempotency_key` row (type `USER`) and its `USER_REGISTERED` row in
`auth_schema.user_creation_audit` are written in one transaction on one connection, started by the persistence adapter
(`JdbcUserRegistrationStore`) and invisible to the use case, which only sees the `UserRegistrationStore` port. Either
all three exist or none does: if the audit insert fails, the user and the key are rolled back with it, so a user can
never exist without the record of who created it. The audit row holds the creator (the `ADMIN`'s user id from the
token), the created user's id, the UTC time, `outcome = SUCCESS` and the request's correlation id.

- First request: `201`. The same key with the same request again: `200` with the same user, nothing created and no
  second audit row (N identical authorized replays leave exactly one).
- **Limit of the actor check.** The existence check and the insert are two steps. `auth_app` has no `DELETE`, and the
  audit foreign keys are `ON DELETE RESTRICT`, so a user that an audit row already names cannot be deleted. An
  administrator who has not yet created anyone could still be removed by a privileged intervention between the check
  and the insert. The foreign key on the audit row's creator is the final protection: the transaction fails as a
  `500` and the user and the key roll back with it, so nothing is created without its audit row. No lock is added
  for that exceptional case.
- The same key with a **different** request: `422 BUSINESS_RULE_VIOLATION` on `Idempotency-Key`. The table keeps no
  fingerprint of the request, so the service compares it with the user the key created (name, email, role and, with
  bcrypt, the password). A key is only an answer to the request that made it: replaying someone else's key must not
  reveal that user's name and email.
- Two simultaneous requests with the same key create one user and both succeed (`201` and `200`).
- A new key with an email that is already registered: `422 BUSINESS_RULE_VIOLATION` with `email` in `details`,
  also when two such requests arrive at once (the unique violation is translated, never a `500`).

**Rejected attempts are not audit records.** `user_creation_audit` holds successful creations only (its
`outcome` is constrained to `SUCCESS`). A `401`, `403`, `400`, `422` or a failure is written to the security log
(logger `synkro.auth.security`, one `WARN` line with the correlation id, the caller's id when there is one and the
reason), after the registration transaction has ended. Those lines never contain the password, its hash, a token, the
request body or a user id: nothing was created, so there is no user to attribute. A `500` caused by a failing audit
write leaves no user and no key behind.

**Emails** are trimmed and lowercased on `register` and on `login`, so `Ana@Example.test` and `ana@example.test`
are one address. A row stored with upper-case letters before this change (for example by an older
`create-local-user.sh`) is not found by `login`; update it to lowercase.

**Errors.** Every error is `{ error, message, details?, traceId }`, with `traceId` equal to the request's
`X-Correlation-Id`, whichever layer raises it. The catalog is closed (`07-api/guidelines.md`).

| Status | `error` | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | invalid or missing field or header (problems in `details`), malformed JSON; also `405` and `415`, which the catalog has no code for |
| 401 | `UNAUTHORIZED` | no token, a fake or expired one, wrong credentials. The gate runs first: an unknown route without a valid token is a `401`, not a `404` |
| 403 | `FORBIDDEN` | a valid token whose role may not do it (`register` or the lookup with a `SALESPERSON`, `INVENTORY` or `SERVICE` token) |
| 404 | `NOT_FOUND` | unknown user or service token id (a malformed id is the same `404`) or an unknown route, for a caller with a valid token |
| 405 | `VALIDATION_ERROR` | a wrong method on a known route, with the `Allow` header, for a caller with a valid token |
| 422 | `BUSINESS_RULE_VIOLATION` | email already registered; idempotency key reused with another request (another user, or another service for a service token) |
| 500 | `INTERNAL_ERROR` | anything unexpected: a fixed message, no stack trace, class name, SQL or host in the body; the cause stays in the log, with the `traceId` |

The `404`, `405` and `500` are produced by `ApiExceptionHandler` in the original dispatch, so the error is never
sent through the servlet error page and the security chain is not asked a second time (the rule that lets only
the `ERROR` dispatch through remains for what the container still renders at `/error`, which has the same envelope).

**Login timing.** A wrong password, an unknown email and a deactivated user run the same single bcrypt verification
(an unknown email is verified against a stand-in hash computed once at startup, at the same cost factor), so their
response times are comparable and a client cannot tell which emails exist. The three bodies are identical. The tests
check the work performed, not the milliseconds.

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" \
  -H "Authorization: Bearer <ADMIN access token>" \
  -d '{"name":"Ana Pérez","email":"ana@example.test","password":"<at least 8 characters>","role":"ADMIN"}'
# 201 {"userId":"…","name":"Ana Pérez","email":"ana@example.test","role":"ADMIN","registrationDate":"…","active":true}

curl -s http://localhost:8080/api/v1/auth/users/<userId> -H "Authorization: Bearer <ADMIN access token>"
```

## Sessions: logout and refresh-token reuse

| Endpoint | Who | Success |
|---|---|---|
| `POST /api/v1/auth/logout` | Any valid access token of `ADMIN`, `SALESPERSON` or `INVENTORY`; a `SERVICE` token gets `403`, decided in `LogoutUseCase` with `RoleGuard`. No token: `401` | `200 { "loggedOut": true }` |

The body is `{ "refreshToken": "<opaque token>" }`; a missing, empty or blank value is `400 VALIDATION_ERROR` with `refreshToken` in `details`.

**Logout is idempotent and does not leak.** It revokes the refresh token (`active = false`) only if it belongs to the caller, is still
active and has not expired. In every other case (unknown, expired, already used, already revoked, or **someone else's token**) it answers
the same `200` and changes nothing, so the response never says whether a token exists or whose it is. The access token is **not
revocable**: it stays valid until it expires, at most one hour after it was issued.

**Reuse detection.** A refresh token works once. Presenting one that was already rotated and has not expired answers `401`
and revokes **every active refresh token of its owner**, including the one the legitimate rotation issued; the user logs in again with
their password. A rotated token that has also expired, and an unknown token, are a plain `401` with no revocation. Only that user's rows
change, and no row is ever deleted (`auth_app` has no `DELETE`): revoking is `active = false`.

The revocation has to survive the `401`. `JdbcRefreshTokenStore` runs it in its own transaction (`PROPAGATION_REQUIRES_NEW`), started by
the adapter so `auth-core` keeps no Spring dependency, so it is committed even if the call that detected the reuse ends in an exception
or runs inside a transaction that rolls back. Neither a token nor its hash is ever returned or logged.

Two behaviors are accepted on purpose, because `refresh_token` has no column to tell the cases apart (`active = false` is all it
records, not whether a row was rotated, logged out or revoked, nor when):

- **A double submit looks like a reuse.** Two concurrent refreshes with the same token (a retry, a double click): one wins and gets a new
  pair; the other finds the token already used and revokes the owner's tokens, including the winner's new one. The user
  logs in again. A grace period would need a "used at" timestamp that the table does not have.

**A revocation and a rotation of the same owner never interleave.** Burning the old token and storing its replacement is one store step
(`RefreshTokenStore.rotate`, one transaction), and both it and `revokeAllOf` take a transaction-scoped advisory lock of that owner first
(`pg_advisory_xact_lock(int, int)`, a key space apart from the bigint key ADR-014 reserves for the initial administrator). A revocation
therefore runs entirely before a rotation (the old token is then already used: a replay) or entirely after it (and it revokes the
replacement too); a replacement can no longer be stored after a revocation ran. Until this was fixed, `consume` and `save` were separate
steps and a revocation between them left the replacement usable
(`RefreshRotationVersusReuseRevocationIntegrationTest`, which covers both orders and a 100-round race on real PostgreSQL).
This is about refresh tokens only: an access JWT that was already issued stays valid until it expires (no early revocation is implemented).
- **A logged-out token presented to `refresh` also looks like a reuse.** It answers `401` and revokes every session of that user. Clients
  must drop the refresh token when they log out and never send it again.

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/logout \
  -H 'Content-Type: application/json' -H "Authorization: Bearer <access token>" \
  -d '{"refreshToken":"<refreshToken from login>"}'
# 200 {"loggedOut":true}
```

## Service tokens

`synkro-workflow` and `synkro-worker` call the other services with a token of their own, never a person's (ADR-006
Decision 2). An `ADMIN` issues it here and stores it as the `SERVICE_TOKEN` secret of the environment.

| Endpoint | Who | Success |
|---|---|---|
| `POST /api/v1/auth/service-tokens` | `ADMIN` only, decided in `IssueServiceTokenUseCase` with `RoleGuard` | `201` + `Location: /api/v1/auth/service-tokens/{id}` and the token, or `200` on a replay with the metadata only |
| `GET /api/v1/auth/service-tokens/{id}` | `ADMIN` only, decided in `GetServiceTokenUseCase` with `RoleGuard` | `200` with the metadata, never the token |

`SALESPERSON`, `INVENTORY` and a `SERVICE` caller get `403 FORBIDDEN` on both (a service token cannot issue or read
tokens); no token is `401`. The role is checked before the input, so a caller who may not issue learns nothing from a
validation error.

**Request.** `{ "service": "synkro-workflow" | "synkro-worker" }` and the header `Idempotency-Key` (8–128 characters,
required). A missing or unknown `service`, or a bad key, is `400 VALIDATION_ERROR` with the field in `details`. Any other
field of the body, such as `permissions`, `issuedBy` or `roles`, is **ignored**: the permissions come from the table below
and `issuedBy` is the `sub` of the verified ADMIN token, never something the client says.

**Response.** `ServiceTokenResponse` is `{ tokenId, service, permissions, issuedBy, issuedAt, expiresAt }`; the `201` adds
`token`. The token is an RS256 JWT with:

| Claim | Value |
|---|---|
| `sub` | the service name |
| `roles` | `["SERVICE"]` |
| `permissions` | the fixed set of that service (below) |
| `jti` | `tokenId` |
| `iat`, `exp` | `issuedAt` and `expiresAt`, whole seconds, `expiresAt = issuedAt + 30 days` |

| Service | Permissions |
|---|---|
| `synkro-workflow` | `customers:read`, `stock:reserve`, `stock:release`, `sales:register` |
| `synkro-worker` | `products:read`, `stock-alerts:read`, `stock-alerts:write` |

The table is code (`ServiceAccount`), not configuration, and `ServiceAccountTest` spells it out: changing a permission
fails the build until the ADR is updated and the test is edited in the same review. The 30-day lifetime is a constant
of `ServiceToken`, not a property, so the invariant `expiresAt = issuedAt + 30 days` cannot be configured away. The token
verifies with this service's own `Rs256TokenVerifier` as a `SERVICE` caller carrying exactly those permissions.

**The token is shown once.** Only the `201` carries it. The `service_token` row keeps the metadata (the table has no column
for the token) and the `idempotency_key` row (type `SERVICE_TOKEN`) points at it; both are written in one transaction by
`JdbcServiceTokenStore`. The token is never stored, logged or returned again.

- The same key and the same `service`: `200` with the metadata, no `token`, nothing created.
- The same key with another `service`: `422 BUSINESS_RULE_VIOLATION` on `Idempotency-Key`; the body shows nothing of the first token.
- Two simultaneous requests with the same key create one row: one `201` with the token, one `200` without it.
- **If a response is lost, issue a new token** with a new key: the first one cannot be recovered, and `GET` only confirms that
  it was issued and when it expires. Rotation is the same: before `expiresAt`, issue a new token, replace the secret and
  restart the service.

**There is no revocation.** Services validate the token locally, so a token stays valid until its own `exp`, also after
a newer one was issued and also if it leaks; the narrow permissions limit the damage (ADR-006, accepted cost). No row of
either table is ever deleted: `auth_app` has no `DELETE`.

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/service-tokens \
  -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" -H "Authorization: Bearer <ADMIN access token>" \
  -d '{"service":"synkro-workflow"}'
# 201 {"tokenId":"…","service":"synkro-workflow","permissions":["customers:read","stock:reserve","stock:release","sales:register"],
#      "issuedBy":"<the ADMIN userId>","issuedAt":"…","expiresAt":"…","token":"eyJ…"}   <- copy it now

curl -s http://localhost:8080/api/v1/auth/service-tokens/<tokenId> -H "Authorization: Bearer <ADMIN access token>"
# 200 the same metadata, without "token"
```

## Token validation

Every request except the public routes must carry `Authorization: Bearer <access token>`. The service
validates the token itself, with the rules every service of the system applies
(`07-api/authentication.md`):

- Only `RS256` is accepted. `none`, `HS256`, `RS384` and every other algorithm are rejected, whatever the token header says.
- The signature is checked with the public key of the key pair that signs the tokens. This service holds the
  private key and **derives the public key from it at startup**, so there is no `JWT_PUBLIC_KEY` to configure
  here and the two can never disagree. A key without its CRT parameters stops the service at startup.
- `exp` and `sub` are required. A clock skew of up to 30 seconds is tolerated.
- Identity, roles and permissions come only from the token's claims (`sub`, `roles`, `permissions`).
  **`X-User-*` headers are ignored**: a request with `X-User-Role: ADMIN` and no token is a `401`, and with a
  valid `INVENTORY` token it is still `INVENTORY`.

A missing token, a fake or malformed Bearer, an expired token, a token signed with another key and an opaque
refresh token are all `401 UNAUTHORIZED`. A valid token whose role does not allow the operation is
`403 FORBIDDEN`; that decision is taken in the use case (`RoleGuard`), not in the controller. Both answer with
the common error envelope `{ error, message, details?, traceId }`, where `traceId` is the request's
`X-Correlation-Id` (generated when the client sends none) and the response echoes that header.

**Public routes** (no token needed): `GET /health`, `POST /api/v1/auth/login` and `POST /api/v1/auth/refresh`.
`register` is not public: an unauthenticated caller must not be able to create or discover accounts. Only those
methods are public: a wrong method on them without a token is a `401`.
Everything else requires a valid token. That includes `POST /api/v1/auth/logout`. An invalid `Authorization` header on a public route is ignored, so an
expired access token never blocks `refresh`.

The caller can carry the token-only role `SERVICE` (see [Service tokens](#service-tokens)); a use case that must refuse
services calls `RoleGuard` without changes to the verifier.
