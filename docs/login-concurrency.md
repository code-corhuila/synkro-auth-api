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
