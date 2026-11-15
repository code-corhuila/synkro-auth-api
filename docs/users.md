# Users

Detailed procedures and delivery notes moved from the repository README at
[source cc45b66](https://github.com/code-corhuila/synkro-auth-api/blob/cc45b6634a40638445123bdcb62063a781249920/README.md).
Recorded execution results retain their original scope; moving them does not
constitute a new execution or certify a different revision.

Run commands from the repository root unless a step explicitly changes directory.

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

## Users: password reset by an ADMIN

HU-AUTH-19. [ADR-021](https://github.com/code-corhuila/synkro-docs/blob/docs/admin-password-reset-decision/05-architecture/decisions/records/ADR-021-admin-password-reset.md)
is **`Accepted`** (revision `a7004cf`, in synkro-docs PR #310; the link is to that branch until the PR is merged). The
acceptance is of the decision: this code and its review are separate facts.

| Endpoint | Who | Success |
|---|---|---|
| `POST /api/v1/auth/users/{id}/password-reset` | A human `ADMIN` whose account exists and is active, decided in `ResetUserPasswordUseCase` itself | `200 { "userId", "passwordResetAt" }` with `Cache-Control: no-store`; the same body on a replay |

Request: `Idempotency-Key` header (8–128 characters, **required**) and body `{ "newPassword", "confirmPassword" }`. The new
password follows the registration policy (8 characters to 72 UTF-8 bytes) and `confirmPassword` must equal it. The
password travels only in the body: it is never in the URL, the response, an error, the audit row or a log, and a value
that is not a JSON string is treated as missing, never converted. Fields the contract does not name are ignored: the
actor is the verified token's subject, and no body field or header can name another one.

**Order of the checks** (nothing below a check runs before it passes): `401` for no or an invalid token, then `403` for a
`SERVICE` token, a role other than `ADMIN`, or an administrator account that is missing or no longer active (stricter
than registration, which only checks that it exists), then `400` for the request (malformed `id`, missing or
out-of-range key, password outside the policy, confirmation that differs; no message repeats a value), then the lookup
of the key, then `404` for an unknown target, then `422` on `id` for a target that is an `ADMIN` or inactive, then the
unit below. So a refused caller learns nothing about a key, and an administrator can never reset **themselves or
another administrator**: the last usable administrator is protected by construction. That is also why this is not an
administrator-recovery path (TD-009 stays open).

**The unit.** `JdbcPasswordResetStore` runs five writes in one transaction on one connection, started by the adapter
and invisible to the use case: it claims the key by inserting the `password_reset_audit` row, takes the per-owner
advisory lock that a refresh rotation and a login issuance also take (`OwnerLock`), replaces the target's hash
(`WHERE active AND role <> 'ADMIN'`, checked again here), sets `active = false` on every active refresh token of the target
and stores the **receipt** (below). If any write fails, all are undone: no key, no audit row, no new hash, no
revocation, no receipt. The hash is computed before the transaction, so no lock is held during bcrypt. The audit row
holds the actor, the target, the key, the UTC time and the correlation id; it holds no password, hash, token or body,
and it is the permanent record of the key.

**The receipt.** `password_reset_receipt` (synkro-auth-db V022 to V026) is a private record, apart from the audit and
linked to it by `audit_id`. It holds exactly the bcrypt string that was just assigned to the target (no second bcrypt, no
password, no body, no fast hash) and `expires_at`, 24 hours after the reset by the **database** clock. `auth_app` can
`SELECT` and `INSERT` it and nothing else; general readers, reports and exports have no access. It never appears in a
response, a log, a `toString` or an error (`RequestReceipt` redacts itself). Expiry is **logical**: a receipt past its
`expires_at` is treated as absent when the key is looked up, whether or not the row has been deleted yet.

**Replay.** The key belongs to the administrator that used it (`UNIQUE (actor_user_id, idempotency_key)`): another
administrator using the same text has a different key, and nobody can read or repeat another's reset. The same key from
the same actor with an *equivalent* request answers `200` with the first execution's body and changes nothing: no new
hash, no revocation (so a session the target opened after the reset survives the replay), no second audit row. Equivalent
means the same target and a password that the **receipt** of that reset verifies. The target's current hash is never the
comparator, so a later reset by another key does not change what this key answers: K1 sets A, K2 sets B, and K1 with A
still answers K1's result without restoring A or revoking the sessions opened after B; K1 with B is `422`. The replay is
read-only and does not even read the target. **After the receipt expires** (24 hours), or if the cleanup removed it, the
same request is `422` on `Idempotency-Key`: the key stays consumed, nothing is executed again, and the answer does not
say the reset did not happen. A new operation needs a new key, chosen by a person. The same key with another target or
password is `422` on `Idempotency-Key`. Two simultaneous requests with one key execute once; both answer `200`.

**Cleanup of expired receipts.** The runtime never deletes. An operator with the right to do so runs
`auth_schema.purge_expired_password_reset_receipts(batch_size)` (1 to 10000, default 1000) **daily**; it deletes only
expired receipts, oldest first, skipping rows another session holds, and returns a count, never a hash. Audits and consumed
keys stay. Project owner **AsolanoT** is assigned daily execution, verification and failure response in the persistent
local installation (confirmed 2026-11-11); this does not install an automated task and needs no new Worker. Details, and
what they do not promise, are in the README of synkro-auth-db: logical expiry is immediate, physical deletion happens when
the procedure runs (not at hour 24), and **a backup taken before it ran still holds the receipt**, so backups are as
sensitive as the live table.

The bounded Auth Portal consumer/provider checks and immutable artifact provenance are documented in
[tests/pact/README.md](../tests/pact/README.md). These checks use a separately created disposable database; they never run
this operational cleanup against the persistent installation.

**An uncertain outcome.** A `500` (persistence failure, or a response lost after the commit) does not say whether the
change was applied. The answer is to repeat the **same** request with the **same** key: it executes if nothing was
committed and answers from the record if it was. Do not generate a new key for a retry, and never reconcile by trying
to log in as the target.

**What a reset does not do.** It revokes refresh tokens only. An access token already issued is stateless and stays valid
until it expires, at most about one hour ([ADR-017](https://github.com/code-corhuila/synkro-docs/blob/main/05-architecture/decisions/records/ADR-017-refresh-reuse-and-jwt-revocation-boundaries.md));
no immediate revocation is claimed. Revoked rows are `active = false` but unexpired, so a stale device that later
presents an old refresh token triggers the existing reuse detection, which revokes every active refresh token of that
owner, including one opened after the reset. There is no forced password change at the next login.

**Login against a reset.** `LoginUseCase` still verifies the password with bcrypt outside any lock. It then hands the
verified hash to `CredentialIssuanceStore.persistRefresh` (`JdbcCredentialIssuanceStore`), which in one transaction takes
the same per-owner lock as the reset and the rotation (same key space, same canonical lower-case user id), reads the user as
it is now, checks that the user is active and that the stored hash **equals the hash that was verified**, and only then
saves the refresh token and commits. If a reset committed in between, or the user was deactivated, the login answers the
generic `401`, saves nothing and returns no token; the claims of the access token come from the identity the unit read.
No column or secret was added for this. Lock order: a rotation and an issuance take the owner lock first and then only read
or insert; a reset claims its audit row first and takes the owner lock before it updates anything; nobody takes two owner
locks, so the three cannot deadlock (`LoginVersusResetIntegrationTest` runs all three together). This closes the window
in which a login verified with the retired password could still store a refresh token after the reset. It is **not**
immediate revocation of an access token that was already issued (ADR-017).

| Status | `error` | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | step 3 above |
| 401 | `UNAUTHORIZED` | no or an invalid token |
| 403 | `FORBIDDEN` | `SALESPERSON`, `INVENTORY` or `SERVICE` token, or an administrator whose account is missing or inactive |
| 404 | `NOT_FOUND` | the target does not exist |
| 422 | `BUSINESS_RULE_VIOLATION` | the target is an `ADMIN` (the caller included) or inactive, or the key was used with a different request |
| 500 | `INTERNAL_ERROR` | persistence failure: the outcome is uncertain, see above |

**Rejected attempts are not audit records.** `password_reset_audit` holds committed resets only. A `401`, `403`, `400`,
`404`, `422` or a failure is one `WARN` line in the security log (`event=PASSWORD_RESET_REJECTED`) with the correlation
id, the caller, the target when it is a well-formed id, and the reason, never a password, key, token or body.

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/users/<userId>/password-reset \
  -H 'Content-Type: application/json' -H "Idempotency-Key: $(uuidgen)" \
  -H "Authorization: Bearer <ADMIN access token>" \
  -d '{"newPassword":"<at least 8 characters>","confirmPassword":"<the same>"}'
# 200 {"userId":"…","passwordResetAt":"…"}
```

The new tables come from `synkro-auth-db` (V018 to V026), so this repository's CI pins `AUTH_DB_REF` to a commit that
has them: the database change is integrated first, then the pin is moved to the merged commit.
