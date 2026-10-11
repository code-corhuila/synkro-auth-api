package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.application.usecase.InitialAdminResult;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException.Kind;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/** HU-AUTH-14: what the operator sees and what the command exits with, without a database. */
class InitialAdminCliTest {

    private static final String ADMIN_PASSWORD = "Initial-Admin-Secret-1";
    private static final String DB_PASSWORD = "db-password-never-printed";
    private static final String DB_URL = "jdbc:postgresql://db.internal:5432/synkro?currentSchema=auth_schema&secretParam=url-secret";

    @TempDir
    Path dir;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private final List<String> logLines = new ArrayList<>();
    private final Deque<char[]> typed = new ArrayDeque<>();
    private final List<String> prompts = new ArrayList<>();
    private final AtomicInteger storeBuilds = new AtomicInteger();
    private final Map<String, String> env = new HashMap<>();
    private SystemUser savedAdmin;
    private InitialAdminStore.InitializationAudit savedAudit;
    private RuntimeException storeFailure;
    private boolean storeCreates = true;
    private boolean promptAvailable = true;

    @BeforeEach
    void connectionSettings() {
        env.put("SPRING_DATASOURCE_URL", DB_URL);
        env.put("SPRING_DATASOURCE_USERNAME", "auth_app");
        env.put("SPRING_DATASOURCE_PASSWORD", DB_PASSWORD);
        env.put("SYNKRO_INIT_OPERATOR", "deploy-pipeline@release-7");
    }

    private int run(String... args) {
        InitialAdminCli.PasswordPrompt prompt = label -> {
            prompts.add(label);
            return !promptAvailable || typed.isEmpty() ? null : typed.removeFirst();
        };
        InitialAdminCli cli = new InitialAdminCli(env, prompt, new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8), settings -> {
                storeBuilds.incrementAndGet();
                return (admin, audit) -> {
                    if (storeFailure != null) {
                        throw storeFailure;
                    }
                    savedAdmin = admin;
                    savedAudit = audit;
                    return new InitialAdminResult(storeCreates, storeCreates ? admin.getUserId() : null);
                };
            }, (outcome, operator, reason, correlationId) ->
                logLines.add("outcome=" + outcome + " operator=" + operator + " reason=" + reason + " correlationId=" + correlationId));
        return cli.run(args);
    }

    private Path passwordFile(String content) throws Exception {
        Path file = Files.createTempFile(dir, "admin-password", ".txt");
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file;
    }

    private String stdout() {
        return out.toString(StandardCharsets.UTF_8);
    }

    private String stderr() {
        return err.toString(StandardCharsets.UTF_8);
    }

    private String everythingTheOperatorCouldSee() {
        return stdout() + stderr() + String.join("\n", logLines);
    }

    private int runWithFile(String... extra) throws Exception {
        List<String> args = new ArrayList<>(List.of("--name", "Ada Admin", "--email", "Ada@Synkro.test",
            "--password-file", passwordFile(ADMIN_PASSWORD + "\n").toString()));
        args.addAll(List.of(extra));
        return run(args.toArray(String[]::new));
    }

    // ── outcomes ────────────────────────────────────────────────────────────

    @Test
    void createsTheAdministratorFromASecretFileAndReportsUserAndCorrelationIds() throws Exception {
        int exit = runWithFile("--correlation-id", "init-corr-42");

        assertThat(exit).isEqualTo(0);
        assertThat(stdout()).contains("result=created").contains("userId=" + savedAdmin.getUserId())
            .contains("correlationId=init-corr-42");
        assertThat(savedAdmin.getRole()).isEqualTo("ADMIN");
        assertThat(savedAdmin.isActive()).isTrue();
        assertThat(savedAdmin.getEmail()).isEqualTo("ada@synkro.test");
        assertThat(new BcryptPasswordHasher().matches(ADMIN_PASSWORD, savedAdmin.getPasswordHash()))
            .as("the trailing newline of the file is not part of the password").isTrue();
        assertThat(savedAudit.operatorIdentity()).isEqualTo("deploy-pipeline@release-7");
        assertThat(savedAudit.correlationId()).isEqualTo("init-corr-42");
        assertThat(logLines).containsExactly(
            "outcome=CREATED operator=deploy-pipeline@release-7 reason=- correlationId=init-corr-42");
    }

    @Test
    void anAlreadyInitializedEnvironmentIsASuccessfulNoOpThatPrintsNoUserId() throws Exception {
        storeCreates = false;

        int exit = runWithFile("--correlation-id", "init-corr-43");

        assertThat(exit).isEqualTo(0);
        assertThat(stdout()).contains("result=already_initialized").contains("correlationId=init-corr-43").doesNotContain("userId");
        assertThat(logLines).containsExactly(
            "outcome=ALREADY_INITIALIZED operator=deploy-pipeline@release-7 reason=- correlationId=init-corr-43");
    }

    @Test
    void generatesACorrelationIdWhenNoneIsSuppliedAndUsesItEverywhere() throws Exception {
        assertThat(runWithFile()).isEqualTo(0);

        String generated = savedAudit.correlationId();
        assertThat(generated).isNotBlank();
        assertThat(stdout()).contains("correlationId=" + generated);
        assertThat(logLines.get(0)).endsWith("correlationId=" + generated);
    }

    @Test
    void takesTheOperatorFromTheOptionOverTheEnvironment() throws Exception {
        assertThat(runWithFile("--operator", "release-manager@ci-9")).isEqualTo(0);

        assertThat(savedAudit.operatorIdentity()).isEqualTo("release-manager@ci-9");
    }

    @Test
    void readsNameEmailAndPasswordFileFromTheEnvironmentToo() throws Exception {
        env.put("SYNKRO_INIT_ADMIN_NAME", "Env Admin");
        env.put("SYNKRO_INIT_ADMIN_EMAIL", "env@synkro.test");
        env.put("SYNKRO_INIT_ADMIN_PASSWORD_FILE", passwordFile(ADMIN_PASSWORD).toString());

        assertThat(run()).isEqualTo(0);

        assertThat(savedAdmin.getName()).isEqualTo("Env Admin");
        assertThat(savedAdmin.getEmail()).isEqualTo("env@synkro.test");
    }

    // ── protected input ─────────────────────────────────────────────────────

    @Test
    void readsThePasswordWithoutEchoAndAsksForItTwice() {
        typed.add(ADMIN_PASSWORD.toCharArray());
        typed.add(ADMIN_PASSWORD.toCharArray());

        int exit = run("--name", "Ada Admin", "--email", "ada@synkro.test");

        assertThat(exit).isEqualTo(0);
        assertThat(prompts).hasSize(2);
        assertThat(new BcryptPasswordHasher().matches(ADMIN_PASSWORD, savedAdmin.getPasswordHash())).isTrue();
    }

    @Test
    void aMismatchedConfirmationFailsWithoutCreatingAnything() {
        typed.add(ADMIN_PASSWORD.toCharArray());
        typed.add("another-password-1".toCharArray());

        int exit = run("--name", "Ada Admin", "--email", "ada@synkro.test");

        assertThat(exit).isEqualTo(2);
        assertThat(savedAdmin).isNull();
        assertThat(stderr()).contains("do not match");
        assertThat(everythingTheOperatorCouldSee()).doesNotContain(ADMIN_PASSWORD).doesNotContain("another-password-1");
    }

    @Test
    void withoutAProtectedPromptItRequiresTheSecretFileAndNeverFallsBackToAnEchoingReader() {
        promptAvailable = false;

        int exit = run("--name", "Ada Admin", "--email", "ada@synkro.test");

        assertThat(exit).isEqualTo(2);
        assertThat(stderr()).contains("--password-file");
        assertThat(savedAdmin).isNull();
        assertThat(storeBuilds.get()).isZero();
    }

    @Test
    void refusesAPasswordGivenAsAnArgumentWithoutRepeatingIt() {
        int exit = run("--name", "Ada Admin", "--email", "ada@synkro.test", "--password", "Typed-On-The-Command-Line-9");

        assertThat(exit).isEqualTo(2);
        assertThat(stderr()).contains("never accepted as an argument");
        assertThat(everythingTheOperatorCouldSee()).doesNotContain("Typed-On-The-Command-Line-9");
        assertThat(storeBuilds.get()).isZero();
    }

    @Test
    void refusesAMissingEmptyOrUnreadableSecretFile() throws Exception {
        assertThat(run("--name", "Ada", "--email", "a@b.co", "--password-file", dir.resolve("missing").toString())).isEqualTo(2);
        assertThat(run("--name", "Ada", "--email", "a@b.co", "--password-file", passwordFile("\n").toString())).isEqualTo(2);
        assertThat(run("--name", "Ada", "--email", "a@b.co", "--password-file", dir.toString())).isEqualTo(2);

        assertThat(savedAdmin).isNull();
        assertThat(stderr()).contains("password file");
    }

    @Test
    void doesNotDeleteTheOperatorsSecretFile() throws Exception {
        Path file = passwordFile(ADMIN_PASSWORD);

        assertThat(run("--name", "Ada", "--email", "a@b.co", "--password-file", file.toString())).isEqualTo(0);

        assertThat(file).exists();
    }

    // ── invalid configuration and input ─────────────────────────────────────

    @Test
    void aMissingOrBlankOperatorIdentityFailsBeforeAnyDatabaseWork() throws Exception {
        env.remove("SYNKRO_INIT_OPERATOR");
        assertThat(runWithFile()).isEqualTo(2);
        assertThat(stderr()).contains("operator");

        env.put("SYNKRO_INIT_OPERATOR", "   ");
        assertThat(runWithFile()).isEqualTo(2);
        assertThat(runWithFile("--operator", "o".repeat(201))).isEqualTo(2);

        assertThat(savedAdmin).isNull();
        assertThat(storeBuilds.get()).isZero();
    }

    @Test
    void invalidAdministratorDataIsReportedByFieldWithoutTheirValues() throws Exception {
        int exit = run("--name", " ", "--email", "not-an-email", "--password-file", passwordFile("short").toString());

        assertThat(exit).isEqualTo(2);
        assertThat(stderr()).contains("name").contains("email").contains("password");
        assertThat(everythingTheOperatorCouldSee()).doesNotContain("not-an-email").doesNotContain("short\n");
        assertThat(savedAdmin).isNull();
        assertThat(storeBuilds.get()).isZero();
    }

    @Test
    void missingNameOrEmailAndUnknownOptionsAreUsageErrors() throws Exception {
        assertThat(run("--email", "a@b.co", "--password-file", passwordFile(ADMIN_PASSWORD).toString())).isEqualTo(2);
        assertThat(run("--name", "Ada", "--password-file", passwordFile(ADMIN_PASSWORD).toString())).isEqualTo(2);
        assertThat(runWithFile("--bogus", "x")).isEqualTo(2);
        assertThat(runWithFile("--name")).isEqualTo(2);

        assertThat(savedAdmin).isNull();
    }

    @Test
    void connectionSettingsThatAreMissingOrNotAuthAppFailWithoutRepeatingAnyValue() throws Exception {
        env.remove("SPRING_DATASOURCE_URL");
        assertThat(runWithFile()).isEqualTo(2);
        assertThat(stderr()).contains("SPRING_DATASOURCE_URL");

        env.put("SPRING_DATASOURCE_URL", DB_URL);
        env.put("SPRING_DATASOURCE_USERNAME", "postgres");
        assertThat(runWithFile()).isEqualTo(2);
        assertThat(stderr()).contains("must be auth_app");

        assertThat(storeBuilds.get()).isZero();
        assertThat(everythingTheOperatorCouldSee()).doesNotContain(DB_PASSWORD).doesNotContain("url-secret");
    }

    @Test
    void anEmailAlreadyUsedByAnotherUserIsAnInputError() throws Exception {
        storeFailure = new BusinessRuleViolationException("email", "The email is already registered");

        assertThat(runWithFile()).isEqualTo(2);
        assertThat(stderr()).contains("email");
        assertThat(logLines.get(0)).startsWith("outcome=REJECTED");
    }

    // ── operational failures ────────────────────────────────────────────────

    @Test
    void aLockTimeoutExitsThreeAndTellsTheOperatorWhatToCheckBeforeRetrying() throws Exception {
        storeFailure = new InitializationFailedException(Kind.LOCK_TIMEOUT, "55P03");

        assertThat(runWithFile("--correlation-id", "c-timeout")).isEqualTo(3);

        assertThat(stderr()).contains("lock").contains("10 seconds").contains("c-timeout");
        assertThat(stdout()).doesNotContain("userId").doesNotContain("result=");
        assertThat(logLines).containsExactly(
            "outcome=LOCK_TIMEOUT operator=deploy-pipeline@release-7 reason=55P03 correlationId=c-timeout");
    }

    @Test
    void aDatabaseFailureExitsFourWithoutAnyDriverMessage() throws Exception {
        storeFailure = new InitializationFailedException(Kind.DATABASE, "08006");

        assertThat(runWithFile()).isEqualTo(4);

        assertThat(stderr()).contains("08006");
        assertThat(stdout()).doesNotContain("userId");
        assertThat(everythingTheOperatorCouldSee()).doesNotContain(DB_PASSWORD).doesNotContain("db.internal").doesNotContain("url-secret");
    }

    @Test
    void anUncertainCommitExitsFiveWithoutClaimingARollback() throws Exception {
        storeFailure = new InitializationFailedException(Kind.OUTCOME_UNCERTAIN, "08006");

        assertThat(runWithFile("--correlation-id", "c-unsure")).isEqualTo(5);

        assertThat(stderr()).contains("could not be confirmed").contains("run the command again").contains("c-unsure");
        assertThat(stderr()).doesNotContain("rolled back");
        assertThat(stdout()).doesNotContain("userId");
    }

    @Test
    void anUnexpectedFailureExitsOneNamingOnlyTheExceptionType() throws Exception {
        storeFailure = new IllegalStateException("boom with " + DB_PASSWORD);

        assertThat(runWithFile()).isEqualTo(1);

        assertThat(stderr()).contains("IllegalStateException");
        assertThat(everythingTheOperatorCouldSee()).doesNotContain(DB_PASSWORD);
    }

    // ── sensitive data ──────────────────────────────────────────────────────

    @Test
    void neverPrintsOrLogsAPasswordHashOrConnectionSecretOnSuccess() throws Exception {
        assertThat(runWithFile()).isEqualTo(0);

        String seen = everythingTheOperatorCouldSee();
        assertThat(seen).doesNotContain(ADMIN_PASSWORD).doesNotContain(savedAdmin.getPasswordHash())
            .doesNotContain(DB_PASSWORD).doesNotContain("url-secret").doesNotContain("db.internal");
    }
}
