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

There is no register endpoint until HU-AUTH-09 and `synkro-auth-db` seeds no users, so a new local database has
nobody to log in as. `scripts/create-local-user.sh` hashes a password with bcrypt on your machine and inserts the
row as `auth_app`; nothing with a password or a hash is committed:

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
Emails are matched exactly as stored; normalization comes with the register story.

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
Everything else requires a valid token. An invalid `Authorization` header on a public route is ignored, so an
expired access token never blocks `refresh`.

The caller can carry the token-only role `SERVICE` (service tokens, later story); a use case that must refuse
services calls `RoleGuard` without changes to the verifier.
