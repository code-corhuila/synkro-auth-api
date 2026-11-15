# QA promotion candidate — authentication security controls

Branch `qa-authentication-security-controls`, based on QA `b9c2b1f`. This note records the promotion scope; validation results are recorded below.

## Scope

| Issue (synkro-docs) | Control | Document |
| --- | --- | --- |
| #278 | Account-based login protection (failure threshold, escalating cooldown) | [login-account-protection.md](login-account-protection.md) |
| #279 | Bounded login concurrency (bulkhead) | [login-concurrency.md](login-concurrency.md) |
| #280 | Gateway registration security regression (real Gateway, Auth, PostgreSQL) | [gateway-registration-security.md](gateway-registration-security.md) |

## Source integration to QA cherry-pick

Each develop integration merge was applied with `cherry-pick -x -m1`.

| Issue | Source integrated SHA (develop) | QA cherry-pick |
| --- | --- | --- |
| #278 | `3ea8278cefdae65368660444c99b6a377e6a2b2e` | `c4276d37ed5d5d2ed96e75aecc74d5bd64cf5207` |
| #279 | `5186fc03be50258d726ebfa1337dd00fe6e00068` | `8dc80ae0b1a16d0487ae2b5d8d9f5928a7d8071e` |
| #280 | `12557403a4e486b87db1eb0eefd85710cecd9be9` | `23ec5c2ce5a1cce9a9eb232f6633a92f7b4cf93b` |

The source revisions are the verified integration commits of Auth PRs #49, #50 and #52, respectively.

## Pinned dependencies

| Dependency | Immutable revision | Where |
| --- | --- | --- |
| `synkro-auth-db` (integrated QA) | `a4810a0fa30f4f8eb73504e7249a9667c45384e8` | `AUTH_DB_REF` in the `integration-tests` job, the `gateway-registration-security` checkout, and the default of `AUTH_DB_REF` in `scripts/auth15/fixture.sh` |
| `synkro-api-gateway` (integrated QA) | `81c8125dda619dadda2163a0f0e2e50b84b10583` | the `gateway-registration-security` checkout and the default of `GATEWAY_REF` in `scripts/auth15/fixture.sh` |
| `synkro-auth-portal` | unchanged (`AUTH_PORTAL_REF`) | `integration-tests` job |

The earlier develop-side pins (`2b62522…` for the database, `24a4ab1…` for the Gateway) are no longer used by the workflow or the fixture. Earlier references in existing design guides and evidence describe historical develop validation; those files are preserved.

## Limitation: state is per process

The account cooldown state and the login concurrency budget live in memory in each Auth process. They reset on restart and are not shared across replicas, so a replicated deployment gets one budget per instance. The Gateway's independent IP limit is unchanged. A shared quota would need an atomic shared adapter and is out of scope.

## Local validation of this QA candidate

Candidate `b3069a22214f1532572d1fbc0b97cefcee8557cf` was validated against the QA dependency pins above on an owned disposable stack. The existing QA deployment was not changed.

- [x] Maven `clean verify`: 758 tests; zero failures, errors or skips; global line coverage 96.02%. Module coverage gates passed.
- [x] Real Gateway -> Auth -> PostgreSQL: 52/52 checks, including forbidden ADMIN registration requests, replay, persistence counts, rollback and restart.
- [x] Pact: 5 Auth Portal interactions passed against real Auth and PostgreSQL. The incompatible HTTP provider was reached and rejected; replay/no-effect postconditions passed.
- [x] Consumer contract digest matches the pinned original and the local copy.
- [x] Actionlint (external ShellCheck not run), Node syntax and `git diff --check` passed.
- [x] Owned fixture cleanup completed; verifier container removed.
- [ ] Hosted QA PR checks: pending at preparation; consult the PR for current status. Local results do not establish a hosted CI pass.
- [ ] Team review and integration through the QA pull request.

Sanitized results: [qa-authentication-security.json](evidence/qa-authentication-security.json).

Historical develop counts (754/745/52) in existing evidence remain unchanged. The local Pact run executed the repository verifier on the disposable provider; it does not claim execution of the hosted `ci-provider.sh` job.
