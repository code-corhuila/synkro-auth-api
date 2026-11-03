# HU-AUTH-15 — Verify real ADMIN user registration and subsequent login

Story: [code-corhuila/synkro-docs#292](https://github.com/code-corhuila/synkro-docs/issues/292). Branch `test/verify-admin-user-registration`,
cut from `develop` at `38ed031`. This document is the design and the case map. It was written **before** any production
change; the execution record is in section 7 and is filled only with runs that really happened.

The registration, its transactional audit and the initial administrator already exist (HU-AUTH-09/13/14). This story does
not rebuild them, adds no endpoint and no migration, and does not implement the users screen (HU-AUTH-16). It verifies the
current integration through the real chain **Gateway → Auth → PostgreSQL** and corrects only a defect it reproduces.

## 1. Sources

Read from `synkro-docs` @ `e975c3f` (read only): `02-domain/entities-and-rules.md`, `02-domain/domain-map.md`,
`07-api/contracts/openapi/synkro-auth-api.yaml` 2.1.1 and `_shared.yaml`, ADR-006 (local token validation), ADR-014
(admin-only registration), ADR-016 (client retry reuses the key), ADR-017 (access tokens are not revocable before expiry),
`11-quality/testing-strategy.md` (AUTH-REG-01…04, evidence levels), `00-governance/definition-of-ready.md` and
`definition-of-done.md`.

Rules that bind this story:

- `POST /api/v1/auth/register` is ADMIN-only. Missing/invalid credentials → 401, valid non-ADMIN or SERVICE → 403, and the
  role check runs **before** the idempotency lookup, so a refused caller learns nothing about a key (ADR-014 Decision 1).
- `Idempotency-Key` (8–128 chars) is required. First success `201` + `Location: /api/v1/auth/users/{id}`; an authorized
  replay `200` with the same user; the same key with a different request is refused; a repeated email is
  `422 BUSINESS_RULE_VIOLATION` naming `email`; `SERVICE` cannot be requested; passwords are bcrypt-hashed and never returned.
- User, idempotency key and the `USER_REGISTERED` audit row commit in one transaction; any failure rolls all three back.
- The audit table never holds a password, hash, token or raw payload.
- A token for an ADMIN stays valid until it expires (ADR-017): this story does not claim immediate revocation.

## 2. Non-goals

Public sign-up, list-all, edit, delete, password recovery, endpoints that force states, re-initialization or reset of any
existing ADMIN, the users web screen, any OpenAPI or migration change, and the shared ADMIN-only security task (#280, below).

## 3. Verification levels used

| Level | What it is here | What it proves | What it does not prove |
|---|---|---|---|
| Unit / port fakes | `auth-core` tests with fakes | use-case rules, ordering, validation | persistence, HTTP |
| Controlled HTTP | Spring `@SpringBootTest` on a random port, tokens **minted by the test with its own key** | boundary, envelope, authorization, atomicity over a real schema | that a token obtained by a real login works end to end |
| Real PostgreSQL | adapter and HTTP tests over a database built by Flyway from `synkro-auth-db` | mapping, constraints, grants, concurrency, rollback | the packaged service or the gateway |
| Real stack (new) | `scripts/auth15/fixture.sh` + `e2e.mjs`: the packaged Auth image, the Gateway image and PostgreSQL on an owned network | login-derived ADMIN token through the Gateway, persistence across restarts, logs | HA or production sizing |

The ADMIN used by the real-stack run is the one the HU-AUTH-14 command creates in the owned database; its token comes from
`POST /api/v1/auth/login`. Negative tokens (expired, other key, `alg:none`) are signed by the script with the **fixture's
own** signing key, which the script owns.

## 4. Real-stack fixture design

Every object is named `auth15-*` and labelled `synkro.task=auth-15`; commands address them by exact name.

| Object | Name | Notes |
|---|---|---|
| network | `auth15-net` | own network; `platform` is not used |
| volume | `auth15-pgdata` | own data |
| PostgreSQL | `auth15-pg` | `postgres:16.15-alpine3.23`, database `synkro_auth_disposable_auth15`, host `127.0.0.1:15435` |
| schema | built by the pinned Flyway image from `synkro-auth-db` @ `c338bf95` | same recipe as the CI job; `auth_app` login role created like the bootstrap does |
| Auth | `auth15-auth-api` | image built from `deploy/Dockerfile` at the exact revision; alias `synkro-auth-api` |
| Gateway | `auth15-gateway` | image built from `synkro-api-gateway` @ `24a4ab1` (`git archive`, no checkout touched); host `127.0.0.1:18085` |
| first ADMIN | created by the packaged `InitialAdminCli` | no reset of any existing ADMIN: the database is new |

Secrets (database passwords, the signing key, the ADMIN password) are generated into a private directory outside the
repository, passed by `--env-file` or mounted read-only, and are never printed. The coordination lease
`HEAVY-DOCKER.lock` is created exclusively before any build and removed only by its owner after teardown. Teardown
(`fixture.sh down`) removes only the objects above by name; no prune, no `down -v`, no process of another task is stopped.
Fault injection stays inside the owned database (`REVOKE`/`GRANT` of INSERT on the audit table) and the owned containers
(restart); there is no production endpoint or flag for it.

## 5. Case map

"Existing" lists the tests already in the repository (names abbreviated; packages under `co.edu.corhuila.synkro.auth`).
"New" lists what this story adds. Nothing in "Existing" is re-implemented.

### AUTH15-01 — Create and authenticate

| Aspect | Existing | New |
|---|---|---|
| ADMIN creates each permitted role, attributed to the token subject | unit `RegisterUserUseCaseTest`, `RegisterUserAttributionTest`; HTTP `RegisterAdminOnlyHttpIntegrationTest.anAdminCreatesEachPermittedHumanRole…` | E2E-03, E2E-07 |
| 201, `Location`, body without password or hash | HTTP `RegisterAndLookupHttpIntegrationTest.register_creates201WithLocation…` | E2E-03, E2E-04 |
| Safe read by known id | `…anAdminReadsAUser_andTheBodyNeverCarriesTheHash`, `…anAdminWhoLoggedInForReal_canReadTheUserTheLocationPointsTo` | E2E-05 |
| New account logs in | `…aRegisteredUser_canLogIn` (controlled token for the creating ADMIN) | E2E-01/02/06: ADMIN token from a **real login through the Gateway**; the new user's token carries its own id and role |
| Hash stored, not password | `JdbcUserRegistrationStoreIntegrationTest.registerUserWithAttribution_persistsEveryColumn…` | E2E-08 |

### AUTH15-02 — Reject unauthorized registration (coordinated with #280)

Issue #280 owns the shared ADMIN-only security case. This story records, and does not re-own, the registration slice:
the same per-role 401/403 families already exist in `RegisterAdminOnlyHttpIntegrationTest` and
`RegisterUserAuthorizationTest`. The new checks only prove the behavior through the Gateway with real login-derived
SALESPERSON/INVENTORY tokens and a genuine SERVICE token, which #280 can cite instead of duplicating.

| Aspect | Existing | New |
|---|---|---|
| Missing / malformed / expired / bad-signature → 401, nothing written | `RegisterAdminOnlyHttpIntegrationTest.unauthenticated_*`; gateway `tests/smoke.sh` (missing header only) | E2E-12 (adds `alg:none`, other-key, refresh-token-as-bearer) |
| SALESPERSON, INVENTORY → 403 | `…forbidden_aValidTokenForAnotherHumanRole_is403…`; `RegisterUserAuthorizationTest.forbidden_aHumanThatIsNotAnAdmin…` | E2E-13 (real logins) |
| SERVICE → 403, also on a replay of an existing key | `…forbidden_aServiceToken_is403_evenWithAKeyThatAlreadyCreatedAUser…`; `RegisterUserOrderTest.ordering_a RefusedReplay…` | E2E-13, E2E-14 |
| **Replay of an existing authorized request by a non-allowed human** (SALESPERSON, INVENTORY) | unit-level only (ordering test); no HTTP/DB case for human non-ADMIN | E2E-14 (and see §6 G2) |
| Signed ADMIN token for a user that does not exist → 403 | `…subject_anAdminTokenWithAWellFormedUuidThatDoesNotExist_is403…` | E2E-15 |
| No mutation during refusals | `…_andWritesNothing` family | E2E-16 |

### AUTH15-03 — Idempotency and invalid data

| Aspect | Existing | New |
|---|---|---|
| Replay → 200, same user, one audit row | `…replay_replayingTheSameAuthorizedRequestAndKey_is200…`; `JdbcUserRegistrationAuditIntegrationTest.replay_…` | E2E-18, E2E-19 |
| Same key, other body → 422, nothing disclosed | `…theSameKeyWithADifferentBody_is422…`; `RegisterUserIdempotencyTest` | E2E-21 |
| Duplicate email → 422 `email`, no key left | `…anExistingEmailWithANewKey_is422…`; `JdbcUserRegistrationStoreIntegrationTest.aDuplicateEmailWithANewKey…` | E2E-22, E2E-23 |
| Invalid fields / key → 400, nothing written | `…anInvalidField_is400ValidationError…`, `…aMissingOrOutOfRangeKey…`; `RegisterUserUseCaseTest` | E2E-24, E2E-25 |
| Concurrent same key → one user, one audit | `…twoSimultaneousRequestsWithTheSameKey…`, `JdbcUserRegistrationAuditIntegrationTest.concurrency_…` | E2E-26 |
| Replay by a *different* ADMIN | none | E2E-20; behavior recorded, see §6 G3 |

### AUTH15-04 — Persistence and privacy

| Aspect | Existing | New |
|---|---|---|
| User + key + audit atomic | `JdbcUserRegistrationAuditIntegrationTest.atomicity_…`; `RegisterAdminOnlyHttpIntegrationTest.atomicity_…` | E2E-09, E2E-10 |
| Audit failure rolls everything back | `…rollback_anAuditWriteThatFails…`, `…rollback_anAuditRowThatBreaksItsOwnConstraint…`, `RegisterAuditFailureHttpIntegrationTest` (in process) | E2E-27, E2E-28, E2E-29 (packaged service; failure injected by an owned `REVOKE`; same key succeeds afterwards) |
| Audit is append-only for `auth_app` | `…theServiceRoleCanOnlyInsertAndReadAuditRows…` | not repeated |
| Survives an owned-store restart | **none** | E2E-30, E2E-31 (database restart), E2E-32 (Auth restart, replay still answers) |
| No password, token or hash in logs, audit or keys | `RegisterRejectionLogHttpIntegrationTest.rejectedAttempts_…LeakNothing` (rejections only) | E2E-33, E2E-34 (Auth logs, Gateway logs, audit rows, key rows, after the whole run) |

## 6. Gap analysis and defect policy

Gaps found by reading before running anything:

- **G1** — no existing test uses an ADMIN token that came from a real login, nor goes through the Gateway. Covered by E2E.
- **G2** — the HTTP/DB tests refuse a SERVICE replay, but a human SALESPERSON/INVENTORY replay of an existing key is
  proven only at unit level. Covered by E2E-14; a controlled-HTTP regression is added if the real stack shows a difference.
- **G3** — replay by a different ADMIN is not specified by the contract text beyond "authorized replay"; the code answers
  200 with the original user and writes no second audit row. It is recorded as the current behavior, not asserted as a
  new rule.
- **G4** — no test restarts the store.

Defect policy: a finding becomes a production change only after a **behavioral** test fails for the right reason at a
recorded revision (RED), the smallest fix in the right hexagonal layer turns it GREEN, and the existing JaCoCo thresholds
(domain ≥ 90 %, application ≥ 80 %, global ≥ 80 %, infrastructure ≥ 60 % per package with a database) still hold. A
failure of the harness itself is fixed in the harness and is not reported as a functional RED.

## 7. Execution record

Executed on 2026-11-02 on one Windows 11 workstation, Docker Desktop, Java 21, Maven 3.9.9 (offline, shared `~/.m2`).
Evidence is sanitized: no password, token, hash or response body is recorded.

**Revisions that ran.** Auth code and tests: `eb20ffe` (branch `test/verify-admin-user-registration`, base `develop` 38ed031).
This story changed no production file, so the production sources are those of 38ed031. Schema: `synkro-auth-db` @ `c338bf95`
through `flyway/flyway:11.20.3-alpine`. Gateway: `synkro-api-gateway` @ `24a4ab1` (`nginx:1.27-alpine`). PostgreSQL
`postgres:16.15-alpine3.23`. The Auth image was built from `deploy/Dockerfile` at `eb20ffe`. Commits after `eb20ffe` change
only this document.

| # | Level | Scope | Result |
|---|---|---|---|
| R1 | Unit + controlled HTTP, no database | `mvn -o verify` at 38ed031 | core 189 pass; adapters 122 and app 185 run, with 74 and 76 database tests **skipped** (no evidence for those) |
| R2 | Real PostgreSQL (owned `auth15-pg`) | `mvn -o verify` at 38ed031 with `TEST_DATABASE_*` | BUILD SUCCESS; adapters 122, app 216, 0 skipped; every JaCoCo gate met |
| R3 | Real PostgreSQL | same at `eb20ffe` | BUILD SUCCESS; core 189, adapters 122, app 218 (+2: the new replay case), 0 failed, 0 skipped; every JaCoCo gate met (domain ≥ 90 %, application ≥ 80 %, global ≥ 80 %, infrastructure ≥ 60 % per package) |
| R4 | Real stack: Gateway → Auth image → PostgreSQL | `scripts/auth15/e2e.mjs` at `eb20ffe` | 52 of 52 checks pass (ids E2E-01…34; some ids repeat per variant). An earlier run of the same script on an image built at 59fda2d, with the same production code, also passed 52 of 52 |

The first R4 attempt failed in the harness, not in the product: the `verify` run had left an ADMIN in the owned database, so
the fixture's own ADMIN did not exist. The harness gained a guarded `reset` and a clear exit; this is not a functional RED.
The first version of the new HTTP case also failed (a user-count difference) because the token helper stores the caller
before the snapshot; the test was corrected, not the product. Neither is a reproduced defect.

**Result.** No defect was reproduced in registration, replay, authorization, persistence or redaction. No production change,
no RED/GREEN pair, no migration and no contract change were therefore made. The coverage of the existing suites was preserved.

### Acceptance criteria and executed evidence

| Criterion | Executed evidence | Limits |
|---|---|---|
| AUTH15-01 | R4 E2E-01…07 (real login of the ADMIN, 201 + Location, safe read, login of the new account, each human role); R2/R3 existing suites | one disposable ADMIN created by the HU-AUTH-14 command in an owned database |
| AUTH15-02 | R4 E2E-11…17 (401 for seven credential faults; 403 for SALESPERSON, INVENTORY and SERVICE on a first attempt and on a replay; no row changed); R3 new case `forbidden_aValidTokenForAnotherHumanRole_replayingAKeyThatCreatedAUser_…` | the expired, other-key and `alg:none` tokens are signed with the fixture's own key; the shared ADMIN-only case belongs to #280, which can cite this evidence instead of repeating it |
| AUTH15-03 | R4 E2E-18…26 (replay 200 once; replay by another ADMIN; changed intention 422; duplicate email 422 in any case; ten invalid inputs 400; eight simultaneous requests give one 201 and seven 200) | a replay by a different ADMIN returns the original user with 200 and writes no second audit row; the contract says no more than "authorized replay", so this is recorded as current behavior |
| AUTH15-04 | R4 E2E-08…10 and 27…34 (bcrypt hash; one attributed audit row; a failing audit insert rolls back user and key and the key is reusable; rows identical after a PostgreSQL restart and an Auth restart; no secret in Auth logs, Gateway logs, audit or key rows); R2/R3 existing rollback and grant tests | restart of a single-node container, not a failover; the fault is an owned `REVOKE`/`GRANT` on the disposable database |

### Not covered

- The users web screen (HU-AUTH-16) and any browser flow.
- Access tokens of a deactivated ADMIN stay valid until they expire (ADR-017); not exercised here.
- Gateway rate limiting beyond staying inside the login budget; the script restarts the owned Gateway to start each run with
  a fresh budget.
- Linux CI: `ci.yml` has not run for this branch yet. All runs above are local on Windows.
- Test-account credentials were not requested; none is delivered or stored.

### Cleanup

`fixture.sh down` removed `auth15-gateway`, `auth15-auth-api`, `auth15-pg`, the volume `auth15-pgdata`, the network
`auth15-net` and the `auth15/*` images by exact name. The private directory with the generated secrets was deleted and the
`HEAVY-DOCKER.lock` created by this task was removed by its owner. Base images pulled for the builds remain in the shared
Docker cache and were not pruned. The synkro-dev project, the `platform` network and every INF-06 and FE-09 resource were not
touched.

### Re-running

```bash
export AUTH15_PRIVATE_DIR=/private/dir/outside/the/repo
scripts/auth15/fixture.sh up        # take the HEAVY-DOCKER.lock lease first while INF-06 is active
node scripts/auth15/e2e.mjs --evidence /private/dir/evidence.json
scripts/auth15/fixture.sh down
```
