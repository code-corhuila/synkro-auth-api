# HU-AUTH-14 — handoff for synkro-docs

Source: `code-corhuila/synkro-auth-api`, branch `feat/initial-admin-cli`. Nothing in synkro-docs was edited; this file
is the input for whoever updates it. The issue number of HU-AUTH-14 is not known here: link it manually.

Evidence is split into **A. automated** (a test or a CI step that fails the build) and **B. manual** (observed once by
a person or an agent in a disposable environment; it is not repeated by CI and must not be cited as automated).

## 1. Traceability

| Requirement | Story | Verified by | Implementation |
|---|---|---|---|
| FR-010 initial administrator | HU-AUTH-14 | AUTH-INIT-01/02/03 (section 2) | `auth-core/.../usecase/InitializeAdminUseCase.java`, `port/out/InitialAdminStore.java`, `auth-adapters/.../jdbc/JdbcInitialAdminStore.java`, `auth-app/.../app/InitialAdminCli.java` |
| NFR-004 atomicity / concurrency | HU-AUTH-14 | AUTH-INIT-01, AUTH-INIT-03 | advisory lock + one READ COMMITTED transaction in `JdbcInitialAdminStore` |
| NFR-009 audit attribution | HU-AUTH-14 | AUTH-INIT-02 (`theCreatedAdministratorAndItsAuditCarryTheAgreedValues`) | audit insert in `JdbcInitialAdminStore.insertAudit` |
| NFR-005 no secrets in output/logs | HU-AUTH-14 | `InitialAdminCliTest` sensitive-data and protected-input groups | `InitialAdminCli`, `InitializationFailedException` |

Paths below are relative to the repository root. Packages: `co.edu.corhuila.synkro.auth`.

## 2. A. Automated evidence

Real PostgreSQL 16, schema built by Flyway from `synkro-auth-db` @ `c338bf95190fc20cbff55c13bb83c279a1febdf9`
(V014–V017), run as `auth_app`.

### AUTH-INIT-01 — concurrency

Class `auth-adapters/src/test/java/co/edu/corhuila/synkro/auth/adapter/out/persistence/jdbc/JdbcInitialAdminStoreIntegrationTest.java`

- `twoOverlappingExecutionsCreateExactlyOneAdministratorAndOneAudit`
- `manyOverlappingExecutionsStillCreateOneAdministrator`
- `theTransactionRunsReadCommittedOnOneAuthAppConnectionHoldingTheReservedKey`

### AUTH-INIT-02 — repetition and no-op

Same class:

- `anExistingActiveAdministratorMakesTheExecutionANoOp`
- `anExistingInactiveAdministratorStillPreventsCreation`
- `usersWithOtherRolesDoNotCountAsAnAdministrator`
- `repeatingTheExecutionAfterASuccessfulOneChangesNothing`
- `theCreatedAdministratorAndItsAuditCarryTheAgreedValues`
- `preexistingUsersAreNeverGivenFabricatedAuthorship`
- `theServiceRoleCanReadAndAppendAuditRecordsButNeverChangeOrRemoveThem`

### AUTH-INIT-03 — rollback, retry and timeout

Same class:

- `anAuditWriteFailureAfterTheUserInsertRollsBothBackAndALaterRetrySucceeds`
- `anEmailAlreadyUsedByAnotherUserIsABusinessRuleAndLeavesNothingBehind`
- `aLockHeldBeyondTheWaitMakesTheExecutionFailWithoutWritingAnything`
- `aRepeatInvocationAfterACommittedCreationIsANoOpEvenIfTheFirstResultWasLost`

Class `auth-adapters/src/test/java/co/edu/corhuila/synkro/auth/adapter/out/persistence/jdbc/JdbcInitialAdminStoreFailureTest.java`
(same story, simulated driver faults, no database needed):

- `aLostCommitConfirmationIsReportedAsUncertainNeverAsARollback`
- `aRefusedConnectionIsADatabaseFailureThatDoesNotRepeatTheUrl`
- `aLockTimeoutStopsBeforeTheExistenceCheckAndWritesNothing`
- `theLockAndTheCheckAreSeparateStatementsInTheAgreedOrder`
- `anExistingAdministratorCommitsWithoutWriting`
- `aFailureWhileWritingRollsBackAndClosesTheConnection`

### Use case and CLI (supporting)

- `auth-core/src/test/java/co/edu/corhuila/synkro/auth/application/usecase/InitializeAdminUseCaseTest.java`:
  `createsFixedActiveAdminWithHashedPasswordAndOperatorAttribution`, `returnsNoopWithoutDisclosingExistingUser`,
  `validatesBeforeHashingIdsOrPersistence`, `commandStringNeverContainsRawInput`.
- `auth-core/src/test/java/co/edu/corhuila/synkro/auth/application/usecase/InitializeAdminOutcomesTest.java`
  (7 tests: timestamps and ids, repeat no-op, field errors without the secret, operator length, store failure, retry,
  failure messages).
- `auth-app/src/test/java/co/edu/corhuila/synkro/auth/app/InitialAdminCliTest.java` (21 tests: outcomes, protected
  input, invalid input, exit codes 1–5, sensitive data).
- `auth-app/src/test/java/co/edu/corhuila/synkro/auth/app/InitialAdminCliIntegrationTest.java`:
  `createsTheAdministratorOnceAndTheSecondRunIsANoOp`,
  `aDatabaseThatCannotBeReachedExitsFourWithoutLeakingTheConnectionSettings`.

### Protection of the destructive cleanup (added after review)

- `auth-adapters/src/test/java/.../jdbc/DisposableDatabaseGuardTest.java` (6 tests) and
  `auth-app/src/test/java/.../app/DisposableDatabaseGuardTest.java` (4 tests): the identity rule, and (adapters) that a
  missing or wrong identity leaves existing rows in place
  (`aMissingOrWrongIdentityPreventsTheCleanupAndKeepsTheRows`).
- CI (`.github/workflows/ci.yml`, job `integration-tests`): fails if `DisposableDatabaseGuardTest`,
  `JdbcInitialAdminStoreIntegrationTest` or `InitialAdminCliIntegrationTest` produced no report or ran no test; fails
  if the migrations lack `operator_identity` (V014) or the V017 grants differ; runs the built jar twice against the
  job's database (`created`, then `already_initialized`) and fails if a listener is open on 8080/8000 on the runner.
  **Not yet executed on GitHub.**

## 3. B. Manual observations (not automated)

All against disposable resources of a single run; nothing was pointed at a shared database.

1. Packaged jar from the host (`java -cp auth-app.jar -Dloader.main=… PropertiesLauncher`): missing operator → exit 2;
   password as an argument → exit 2; create → exit 0 `result=created`; repeat → exit 0
   `result=already_initialized`; lock held by another session for 30 s → exit 3 after the 10 s wait with the user and
   audit counts unchanged.
2. Container form of section 4, image built from `deploy/Dockerfile`: create → exit 0, repeat → exit 0, connected as
   `auth_app` using `SPRING_DATASOURCE_PASSWORD_FILE`; lock held → exit 3.
3. No HTTP listener, tied to the CLI container: with the process waiting for the lock, its network namespace had one
   ESTABLISHED socket to PostgreSQL (port 5432) and one `LISTEN` row at `127.0.0.11` (Docker's DNS resolver), which no
   process of the container owns; the java process held 2 sockets, none listening.
4. The CI guard snippet (`TRUNCATE` after the `current_database()` check) was run as the runner would: it emptied the
   correctly named database and refused (exit 3) on the cluster's `postgres` database, leaving rows intact.

## 4. Invocation to document in the runbook

```bash
docker run --rm --network <database network> \
  -e SPRING_DATASOURCE_URL='jdbc:postgresql://synkro-db:5432/synkro?currentSchema=auth_schema' \
  -e SPRING_DATASOURCE_USERNAME=auth_app \
  -e SPRING_DATASOURCE_PASSWORD_FILE=/run/secrets/auth_app_password \
  -e SYNKRO_INIT_OPERATOR='<deployment identity>' \
  -v <host>/auth_app_password:/run/secrets/auth_app_password:ro \
  -v <host>/initial_admin_password:/run/secrets/initial_admin_password:ro \
  --entrypoint java <service image> \
  -cp /app/auth-app.jar -Dloader.main=co.edu.corhuila.synkro.auth.app.InitialAdminCli \
  org.springframework.boot.loader.launch.PropertiesLauncher \
  --name '<name>' --email '<email>' --password-file /run/secrets/initial_admin_password
```

Exit codes: 0 created or already initialized; 1 unexpected; 2 invalid input/configuration (or email of another user);
3 lock not obtained in 10 s; 4 database failure before commit; 5 commit not confirmed (outcome uncertain).
Lock key `1398361682` (`pg_advisory_xact_lock(bigint)`), READ COMMITTED, `SET LOCAL lock_timeout = '10s'`.

## 5. Still pending

- Gateway login with the created administrator (operational acceptance). Not performed: the gateway running locally
  is a different environment from the disposable database.
- Remote CI run of this branch, including the new dedicated-database steps.
- Human review and approval; HU-AUTH-14 is not Done.
- Updating synkro-docs (FR-010 / NFR-004 / NFR-009 / NFR-005 mapping, runbook, ADR-014 notes).
- Linking the real HU-AUTH-14 issue number.
- Recovery after normal operation starts remains separate work and is not implemented.
