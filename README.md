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

The service signs tokens with an RS256 private key and **refuses to start** without one
(`JWT_PRIVATE_KEY_FILE`, see [Development](#development)).

```bash
export JWT_PRIVATE_KEY_FILE=/path/to/jwt-private.pem
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

## Development

### Signing key

`JWT_PRIVATE_KEY_FILE` must point to an unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`) holding an RSA
key of at least 2048 bits. Generate a throwaway one for local work and keep it out of git:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem   # what other services receive as JWT_PUBLIC_KEY
```

### Temporary seeded users

> **Temporary.** `synkro-auth-db` has no `system_user` or `refresh_token` table yet, so login runs
> against three in-memory users and an in-memory refresh-token store
> (`auth-adapters/.../persistence/inmemory/`). A follow-up story replaces both with Postgres adapters.
> Nothing can create or change a user, and a restart resets everything. These passwords are public:
> never deploy this build anywhere real.

| Email | Password | Role |
|---|---|---|
| `admin@synkro.test` | `admin-dev-password` | `ADMIN` |
| `sales@synkro.test` | `sales-dev-password` | `SALESPERSON` |
| `inventory@synkro.test` | `inventory-dev-password` | `INVENTORY` |

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@synkro.test","password":"admin-dev-password"}'
# {"accessToken":"…","refreshToken":"…","tokenType":"Bearer","expiresIn":3600}

curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken from login>"}'
```

A refresh token works once: using it returns a new pair and invalidates the old token, so replaying it is a `401`.
