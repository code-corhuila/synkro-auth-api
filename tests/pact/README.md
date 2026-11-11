# Auth Portal → Auth API reset contract

The pinned consumer artifact comes from the actual Auth Portal client test; provenance records its immutable source
revision, path and LF-normalized SHA-256. `check-provenance.mjs <clean-consumer-checkout>` compares the Git blob and
copied artifact. CI checks out that exact consumer revision, not a moving branch. Change both the pin and provenance
through review when the consumer contract changes. The provider verifier is pinned by package-lock.json.

The five interactions cover a first reset, K1/A replay after K2/B, an expired receipt, a physically purged receipt,
and a forbidden SALESPERSON. The verifier first proves that an incompatible HTTP provider is reached and rejected,
then uses the real Auth executable with its real owning migrations and PostgreSQL. Provider states register private
users through the API, execute actual resets and check permanent audit counts and current-password login afterwards.
Only fixture expiry is changed through operator SQL; purge calls the owning function. These are controlled states,
not claims of spontaneous expiry or network faults. HTTP/unit/concurrency suites retain their separate coverage.

Contract examples contain `[redacted]` string matchers instead of stored credentials. The provider request filter
injects ephemeral credentials and bearer tokens without changing the tested body fields or status/response shapes.
States return only targetId. No credential, bcrypt or token may be published in an artifact or shared diagnostic.

CI: `npm ci --prefix tests/pact`, provenance check, then `bash tests/pact/ci-provider.sh` after Maven verification.
The executor refuses a dirty/wrong DB checkout, creates its own reserved-name database and initializes an ADMIN with
the packaged operator CLI. It starts its own JVM, uses a bounded startup wait, preserves failure exit codes and
removes only its JVM, labelled migration container, created database and private temporary files. Runtime credentials
never gain cleanup privileges. This executor is disposable acceptance; it does not deploy or clean the persistent store.

Before integrating API #44, DB #27 must be integrated and AUTH_DB_REF re-pinned to its actual develop integration
commit, followed by the affected checks. A feature-head pin is not the final integration pin. Portal follows API.
