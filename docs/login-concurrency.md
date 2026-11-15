# Login concurrency budget — security issue #279

FR-010 / NFR-004. Pattern: Bulkhead. A process-wide admission budget surrounds the synchronous login use case at the HTTP boundary, before any user lookup or password verification. There is no waiting-work queue. Capacity belongs to the actual server operation, not the lifetime of the caller's connection. Exceptions and completion release it through a scoped permit; cancelling a client does not release still-running work.

The composition root declares `AUTH_LOGIN_MAX_CONCURRENT` (initial conservative value 2) and `AUTH_LOGIN_OVERLOAD_RETRY_SECONDS` (1). These are configurable operational starting points, not a throughput guarantee; deployment tuning must use measured CPU/bcrypt/database results. Limits are per Auth process, not a distributed quota. The Gateway's independent IP budget remains unchanged.

## HTTP extension

`POST /api/v1/auth/login` can return `429`, `Retry-After: <positive integer>`, `Cache-Control: no-store`, and the common `TOO_MANY_REQUESTS` envelope with a generic message and correlation reference. It returns no tokens and performs no lookup or verification when full. Refresh, logout and user administration do not consume this budget. Invalid request shape still receives its existing 400.

## Acceptance map

- AC1/2/3: real HTTP controlled verification holds two distinct account operations at the password adapter, checks peak active verification and rejects additional requests before releasing either holder.
- AC4: completion, wrong credentials, adapter exceptions and client cancellation must preserve/recover capacity; a disconnected holder retains its slot until underlying verification finishes.
- AC5: core and HTTP tests run in the existing Maven CI job. Record source, command, request/status counts, configured capacity and peak work in the execution section after actually running. No hosted success is inferred from a workflow declaration.

Canonical Auth OpenAPI/traceability reconciliation is handed off to synkro-docs under the existing documentation process; this owning-service contract extension and its tests precede implementation. No new endpoint, database schema or domain entity is introduced.


## Executed verification — 2026-11-15

`mvn -B -q clean verify` with Java 21.0.12 and the pinned Auth DB schema on owned disposable PostgreSQL: **745 tests, zero failures/errors/skips**. Global LINE coverage: **95.87%**. Existing coverage gates passed unchanged. [Source fingerprints and layer results](evidence/login-concurrency-verification.json).

The initial permissive budget scaffold produced two failing assertions/tests before implementation. The real-HTTP controlled-password run sent seven requests: two observed 200 responses, four 429 responses and one cancelled client; capacity and measured peak password work were both 2, followed by a successful 200 recovery. Completion, invalid credentials and adapter-exception release also passed. Controlled password/user ports distinguish that experiment from the separate real PostgreSQL integration suites in the complete build.

This is local execution, not a GitHub Actions success, independent review, integration, deployment or formal issue closure. Test-first commits introduce the specifications; the following implementation commit makes that snapshot runnable. Original red runs used executable scaffolding in the working tree, not a claim that the later commit had already run.
