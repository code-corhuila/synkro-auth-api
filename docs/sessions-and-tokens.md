# Sessions and tokens

Detailed procedures and delivery notes moved from the repository README at
[source cc45b66](https://github.com/code-corhuila/synkro-auth-api/blob/cc45b6634a40638445123bdcb62063a781249920/README.md).
Recorded execution results retain their original scope; moving them does not
constitute a new execution or certify a different revision.

Run commands from the repository root unless a step explicitly changes directory.

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

The caller can carry the token-only role `SERVICE` (see [Service tokens](../README.md#service-tokens)); a use case that must refuse
services calls `RoleGuard` without changes to the verifier.
