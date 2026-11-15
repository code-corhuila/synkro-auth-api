# Local development

Detailed procedures and delivery notes moved from the repository README at
[source cc45b66](https://github.com/code-corhuila/synkro-auth-api/blob/cc45b6634a40638445123bdcb62063a781249920/README.md).
Recorded execution results retain their original scope; moving them does not
constitute a new execution or certify a different revision.

Run commands from the repository root unless a step explicitly changes directory.

## Running locally

The service signs tokens with an RS256 private key and reads its users and refresh tokens from
PostgreSQL. It **refuses to start** without the key (`JWT_PRIVATE_KEY_FILE`) or without a usable
datasource (`SPRING_DATASOURCE_*`); see [Development](../README.md#development) for both.

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
# 200 {"status":"ok","service":"synkro-auth-api","timestamp":"…","dependencies":{"database":"ok"}}
```

`/health` checks the one dependency of this service, the connection to `auth_schema` (it reads one row of `system_user` as
`auth_app`, with a 3 second limit), as `05-architecture/cross-cutting.md` section 4 asks. When it cannot, the answer is
`503 {"status":"degraded", …, "dependencies":{"database":"down"}}`, with no host, user or driver message in the body or the log.
It is public and does not depend on any other service.

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
(see [Users](../README.md#users-register-and-lookup)) needs an `ADMIN` token. The first administrator therefore has to come from
outside the API. For a real environment that is the audited [initial administrator command](../README.md#initial-administrator).
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

A refresh token works once: using it returns a new pair and invalidates the old token. Replaying it is a `401` and revokes every refresh token of that user (see [Sessions](../README.md#sessions-logout-and-refresh-token-reuse)).
