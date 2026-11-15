# Main promotion - authentication security controls

Promotes synkro-docs issues #278, #279 and #280 from integrated QA PR #53 to main. Branch `release/authentication-security-controls` starts at main `71f9801`.

QA integration `dacaa93897b8a3672146d68b5ddd8bb53b40c68a` was reapplied with `cherry-pick -x -m 1` as `4042ccfd06dc10a2be235c1f1f8fa687892c9e83`. The only conflict was the CI database pin; the existing main pin was retained. Follow-up `778d9a975b798999b37e466bc56c0d1aa20b0dd2` aligns the new Gateway fixture and job with main dependencies:

- Auth DB: `54c7fdce2b027d340d990123b9ae17af4f91ec79`.
- Gateway: `5e5c3d5bdd67ae8c20eba2eaf2241d43a67adcde`.
- Auth Portal contract pin remains unchanged.

## Validation scope

The tracked tree comparison against integrated QA differs only in `.github/workflows/ci.yml` and `scripts/auth15/fixture.sh`. Auth source, tests, build and runtime configuration are otherwise identical. The pinned main DB and Gateway differ from their tested QA revisions only in README/docs files; migrations and Gateway runtime files match.

New targeted Maven execution on the main candidate: 17 tests across five suites passed, with zero failures, errors or skips. This covers account protection, state/locking, admission, HTTP saturation, disconnect and recovery. Actionlint (without external ShellCheck), Node syntax and diff whitespace checks passed.

The earlier QA validation is preserved: 758 tests, 96.02% global line coverage, 52/52 real Gateway/Auth/PostgreSQL checks, and five real Pact provider interactions plus the incompatible-provider negative control. Those full-stack suites were not rerun for main; equivalence and targeted regression checks are recorded separately.

Evidence: [main-authentication-security.json](evidence/main-authentication-security.json), [QA evidence](evidence/qa-authentication-security.json).

## Review and operational limits

- Hosted checks must be assessed on the main PR; local tests do not establish a hosted pass. The earlier QA run was blocked before execution by account billing.
- Main integration requires approval from `ariel5253`; CODEOWNERS and existing protections are unchanged.
- Cooldown state is process-local, resets on restart and is not shared across replicas. Admission is bounded per process; defaults are not production load certification.
- This promotion does not deploy or modify an existing environment. Synkro-docs PR #321 remains outside this change.
