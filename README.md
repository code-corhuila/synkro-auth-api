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

```bash
TEST_DATABASE_URL='jdbc:postgresql://localhost:5432/synkro' TEST_DATABASE_PASSWORD='<auth_app password>' mvn -B verify
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
stored as a SHA-256 hash with an `expiration_date` seven days ahead; rotating it marks the row
`active = false`. A user with `active = false` cannot log in, and gets the same `401` as a wrong password.

### The first local user

`synkro-auth-db` seeds no users, so a new local database has nobody to log in as. The normal way to create one
is now `POST /api/v1/auth/register` (see [Users](#users-register-and-lookup)); it is public, so it needs no
login first. `scripts/create-local-user.sh` remains for local convenience, for example to create an `ADMIN`
without going through the API: it hashes a password with bcrypt on your machine, lowercases the email like the
service does, and inserts the row as `auth_app`; nothing with a password or a hash is committed:

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

A refresh token works once: using it returns a new pair and invalidates the old token, so replaying it is a `401`.

## Users: register and lookup

| Endpoint | Who | Success |
|---|---|---|
| `POST /api/v1/auth/register` | Public: any caller, any of `ADMIN`, `SALESPERSON`, `INVENTORY` (a documented simplification of the academic MVP; there is no authorization on it) | `201` + `Location: /api/v1/auth/users/{id}`, or `200` on a replay; body `UserResponse` |
| `GET /api/v1/auth/users/{id}` | `ADMIN` only, decided in `GetUserUseCase` with `RoleGuard` | `200` `UserResponse` |

`UserResponse` is `{ userId, name, email, role, registrationDate, active }`. The password and its hash are never
returned. `register` takes `{ name (1–150), email (3–255, valid), password (8–72 bytes), role }`; `SERVICE` or any
other role is rejected before the database is touched. The 72-byte ceiling is bcrypt's own limit: a longer
password would be silently truncated.

**Headers.** `Idempotency-Key` (8–128 characters) is **required** on `register`; a missing or out-of-range key is a
`400 VALIDATION_ERROR`. `X-Correlation-Id` is reused if sent, generated otherwise, echoed in every response and used
as the `traceId` of every error. `Authorization: Bearer …` is needed for the lookup only.

**Idempotency.** The user and its `idempotency_key` row (type `USER`) are written in one transaction, started by
the persistence adapter (`JdbcUserRegistrationStore`), so either both exist or neither does.

- First request: `201`. The same key with the same request again: `200` with the same user, nothing created.
- The same key with a **different** request: `422 BUSINESS_RULE_VIOLATION` on `Idempotency-Key`. The table keeps no
  fingerprint of the request, so the service compares it with the user the key created (name, email, role and, with
  bcrypt, the password). A key is only an answer to the request that made it: replaying someone else's key must not
  reveal that user's name and email.
- Two simultaneous requests with the same key create one user and both succeed (`201` and `200`).
- A new key with an email that is already registered: `422 BUSINESS_RULE_VIOLATION` with `email` in `details`,
  also when two such requests arrive at once (the unique violation is translated, never a `500`).

**Emails** are trimmed and lowercased on `register` and on `login`, so `Ana@Example.test` and `ana@example.test`
are one address. A row stored with upper-case letters before this change (for example by an older
`create-local-user.sh`) is not found by `login`; update it to lowercase.

**Errors.** Every error is `{ error, message, details?, traceId }`, with `traceId` equal to the request's
`X-Correlation-Id`, whichever layer raises it. The catalog is closed (`07-api/guidelines.md`).

| Status | `error` | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | invalid or missing field or header (problems in `details`), malformed JSON; also `405` and `415`, which the catalog has no code for |
| 401 | `UNAUTHORIZED` | no token, a fake or expired one, wrong credentials. The gate runs first: an unknown route without a valid token is a `401`, not a `404` |
| 403 | `FORBIDDEN` | a valid token whose role may not do it (the lookup with a `SALESPERSON`, `INVENTORY` or `SERVICE` token) |
| 404 | `NOT_FOUND` | unknown user id (a malformed id is the same `404`) or an unknown route, for a caller with a valid token |
| 405 | `VALIDATION_ERROR` | a wrong method on a known route, with the `Allow` header, for a caller with a valid token |
| 422 | `BUSINESS_RULE_VIOLATION` | email already registered; idempotency key reused with another request |
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
  -d '{"name":"Ana Pérez","email":"ana@example.test","password":"<at least 8 characters>","role":"ADMIN"}'
# 201 {"userId":"…","name":"Ana Pérez","email":"ana@example.test","role":"ADMIN","registrationDate":"…","active":true}

curl -s http://localhost:8080/api/v1/auth/users/<userId> -H "Authorization: Bearer <ADMIN access token>"
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

**Public routes** (no token needed): `GET /health`, `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh` and
`POST /api/v1/auth/register`. Only those methods are public: a wrong method on them without a token is a `401`.
Everything else requires a valid token. An invalid `Authorization` header on a public route is ignored, so an
expired access token never blocks `refresh`.

The caller can carry the token-only role `SERVICE` (service tokens, later story); a use case that must refuse
services calls `RoleGuard` without changes to the verifier.
