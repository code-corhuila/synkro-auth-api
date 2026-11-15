# Gateway registration regression — security issue #280

FR-010 / NFR-004. This is verification of existing ADMIN authorization and atomic registration, not a second registration implementation. Reuse `scripts/auth15/fixture.sh` and `scripts/auth15/e2e.mjs` over an isolated real PostgreSQL, the built Auth application and the real declarative Gateway.

## Acceptance map

- AC1: E2E-03/09/10 verify authorized creation, one user, key and creation-audit row.
- AC2/3: E2E-13 sends an explicit ADMIN registration for each SALESPERSON, INVENTORY and SERVICE caller. Each uses its own fresh email/key; compare the entire successful-write totals and per-operation user/key/audit counts immediately before/after each refusal.
- AC4: E2E-14 reuses an ADMIN's actual key and input under each forbidden caller; compare the original user fingerprint, key count, successful-audit count and global totals for every role.
- AC5: the added CI job runs this exact script against built services, cleans only its labelled fixture and uploads the sanitized result. Existing core RegisterUserOrderTest retains the authorization-before-lookup checks.
- AC6: E2E-18 verifies the authorized 200 replay and exactly one user/key/audit.

The fixture is disposable and separately named. It never targets an existing platform or application database. Revisions of Auth DB and Gateway are pinned, no source credentials are committed and no service is weakened to make a test pass. No production correction is planned unless these regressions expose a defect. New verification cases can pass against already-correct production behavior; this does not reconstruct a fictional failing production test.


## Executed verification — 2026-11-15

The real owned Gateway/Auth/PostgreSQL fixture passed **52/52 checks** with no leaked credential markers. The explicit ADMIN-role negative attempts and per-role zero-write/replay fingerprints passed for SALESPERSON, INVENTORY and SERVICE. The existing authorized replay, rollback and restart checks also passed. [Sanitized check results and revisions](evidence/gateway-registration-security.json). This verifies existing business behavior; it does not fabricate a production defect or a red production run. Hosted CI, review and integration remain separate.
