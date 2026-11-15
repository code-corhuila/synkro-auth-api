# Testing

Detailed procedures and delivery notes moved from the repository README at
[source cc45b66](https://github.com/code-corhuila/synkro-auth-api/blob/cc45b6634a40638445123bdcb62063a781249920/README.md).
Recorded execution results retain their original scope; moving them does not
constitute a new execution or certify a different revision.

Run commands from the repository root unless a step explicitly changes directory.

## Running the tests

```bash
mvn test
```

Unit and HTTP tests need no database. The `*IntegrationTest` classes run only when `TEST_DATABASE_URL`
is set, against a database whose schema was built from `synkro-auth-db`; they connect as `auth_app`
(`TEST_DATABASE_USER` overrides the user, `TEST_DATABASE_PASSWORD` is its password) and never delete
a row, so they can be re-run on the same database.

The one exception is the initial-administrator tests (`JdbcInitialAdminStoreIntegrationTest`,
`InitialAdminCliIntegrationTest`): initialization only happens on a database with no `ADMIN`, and `auth_app` cannot
delete, so each test first **empties `auth_schema`** through the instance administrator. That is destructive, so it
needs a throwaway database, an explicit opt-in and proof of which database it is:
`TEST_DATABASE_DISPOSABLE=true`, `TEST_ADMIN_DATABASE_PASSWORD` (`TEST_ADMIN_DATABASE_USER` defaults to `postgres`)
and `TEST_DISPOSABLE_DATABASE_NAME`. Consent and a password do not say *which* database answers, so before the
`TRUNCATE` the administrative connection asks the server `SELECT current_database()` and the answer must equal
`TEST_DISPOSABLE_DATABASE_NAME`, a name that must start with `synkro_auth_disposable_` (so `synkro`, `postgres` or
any shared name is refused). A missing or different name fails the test with an explanation, before anything is
emptied; the URL is not trusted for this. Without the three settings those tests **fail** rather than skip, and the
command under test still connects only as `auth_app`. Never point them at a shared or persistent database.

```bash
TEST_DATABASE_URL='jdbc:postgresql://localhost:5432/synkro_auth_disposable_local' TEST_DATABASE_PASSWORD='<auth_app password>' \
TEST_DATABASE_DISPOSABLE=true TEST_DISPOSABLE_DATABASE_NAME=synkro_auth_disposable_local \
TEST_ADMIN_DATABASE_PASSWORD='<admin password of the disposable database>' mvn -B verify
```

`mvn -B verify` also enforces the coverage thresholds of `11-quality/testing-strategy.md` with JaCoCo
(module `auth-coverage`): domain ≥ 90 %, application ≥ 80 % and global ≥ 80 % of lines on every run, and
infrastructure (the adapters) ≥ 60 % per package when `TEST_DATABASE_URL` is set. The report is written to
`auth-coverage/target/site/jacoco/index.html`.
