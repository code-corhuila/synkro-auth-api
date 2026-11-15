# Account-based login protection — security issue #278

FR-010 / NFR-004. The application evaluates a normalized account key independently of source IP. Pattern: Policy plus a storage Port/Adapter; a clock controls boundaries. The store hashes normalized email keys, stores no password, and serializes evaluation of one account through completion of verification and its state transition. Known, unknown and inactive accounts use the same failure policy and generic responses.

Defaults: 3 failures in a trailing (rolling) 60-second window; cooldowns 30, 60, 120, 120 seconds; retention 600 seconds after the last evaluated attempt; at most 10,000 retained keys. The third failure still returns 401; the following request returns 429. Rejected cooldown requests do not extend cooldown or retention. Success removes the account state. At the exact deadline normal evaluation resumes. Cleanup runs every 30 seconds and never drops a live operation's state. Exhausted state capacity fails closed with a generic 429; it never evicts an active cooldown to make room.

All policy durations, threshold, retention, capacity and cleanup cadence are explicit composition settings. These conservative single-process defaults need deployment-specific measurement. State is intentionally process-local and resets on restart: it is not a durable or cluster-wide security budget. A replicated Auth deployment needs an atomic shared adapter before claiming a shared quota. This implementation adds no migration or new business entity and never shares another domain's store.

## HTTP extension

Auth's existing POST `/api/v1/auth/login` can return `429`, the common `TOO_MANY_REQUESTS` envelope, `Cache-Control: no-store` and an integer `Retry-After` equal to remaining cooldown seconds rounded upward, at least 1. No token or account-existence detail is returned. The Gateway's independent IP limit remains in place.

## Acceptance map and handoff

Core tests first cover failure thresholds, normalization, success/reset, exact boundaries, non-extension, progression/cap and exception handling. HTTP tests distinguish Auth-generated 429 from Gateway by reaching Auth directly with different source headers. Store tests cover atomic updates, capacity, expiry and cleanup with no dropped active budget. Canonical OpenAPI/traceability reconciliation belongs in synkro-docs; the owning-service extension and tests are documented here before implementation with a separate shared documentation PR authorized by the owner. No accepted ADR is silently edited.


## Executed verification — 2026-11-15

`mvn -B -q clean verify` with Java 21.0.12 and the pinned Auth DB schema on owned disposable PostgreSQL: **754 tests, zero failures/errors/skips**. Global LINE coverage: **95.98%**. Existing coverage gates passed unchanged. [Source fingerprints and layer results](evidence/login-account-protection-verification.json).

Tests were written before the feature. The permissive scaffold run observed three assertion failures and two missing-state errors in six core tests; a later rolling-window boundary regression failed before correction. The final core/HTTP/store suite passed, including capacity/atomicity/expiry and the scheduled cleanup entry point. Account HTTP uses controlled time and in-memory user ports; the rest of the complete build includes the real JDBC/HTTP PostgreSQL suites.

This is local execution, not a GitHub Actions success, independent review, integration, deployment or formal issue closure. Test-first commits introduce the specifications; the following implementation commit makes that snapshot runnable. Original red runs used executable scaffolding in the working tree, not a claim that the later commit had already run.

The follow-up colliding-key regression (Aa/BB) failed against bucket-locked verification. The corrected adapter locks each account entry, holds the map monitor only for allocation/cleanup, and keeps active/queued references so cleanup cannot drop an in-flight account. The final 754-test real-DB run above includes this regression.
