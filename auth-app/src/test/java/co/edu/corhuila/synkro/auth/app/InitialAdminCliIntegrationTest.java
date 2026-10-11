package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The command end to end on the real auth_schema, with the production wiring (own connection, auth_app, the
 * JDBC store): two executions in a row, the second being the no-op. Initialization needs a database with no ADMIN
 * and auth_app cannot delete, so, like the adapter tests, this empties the disposable schema first through the
 * instance administrator and therefore requires TEST_DATABASE_DISPOSABLE=true.
 */
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class InitialAdminCliIntegrationTest {

    private static final String PASSWORD = "Cli-Integration-Secret-1";

    @TempDir
    Path dir;

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private final ByteArrayOutputStream err = new ByteArrayOutputStream();
    private final Map<String, String> env = new HashMap<>();

    @BeforeEach
    void emptyTheDisposableSchema() throws Exception {
        assertThat(System.getenv("TEST_DATABASE_DISPOSABLE")).as("TEST_DATABASE_DISPOSABLE must be 'true'").isEqualTo("true");
        assertThat(System.getenv("TEST_ADMIN_DATABASE_PASSWORD")).as("TEST_ADMIN_DATABASE_PASSWORD must be set").isNotBlank();
        try (Connection c = DriverManager.getConnection(System.getenv(DatabaseTestSupport.URL_VARIABLE),
            System.getenv().getOrDefault("TEST_ADMIN_DATABASE_USER", "postgres"), System.getenv("TEST_ADMIN_DATABASE_PASSWORD"));
             Statement s = c.createStatement()) {
            s.execute("TRUNCATE auth_schema.user_creation_audit, auth_schema.refresh_token, auth_schema.service_token, "
                + "auth_schema.idempotency_key, auth_schema.system_user CASCADE");
        }
        env.put("SPRING_DATASOURCE_URL", System.getenv(DatabaseTestSupport.URL_VARIABLE));
        env.put("SPRING_DATASOURCE_USERNAME", System.getenv().getOrDefault("TEST_DATABASE_USER", "auth_app"));
        env.put("SPRING_DATASOURCE_PASSWORD", System.getenv("TEST_DATABASE_PASSWORD"));
    }

    private int run(String... args) {
        return new InitialAdminCli(env, label -> null, new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8), InitialAdminCli::postgresStore,
            (outcome, operator, reason, correlationId) -> { }).run(args);
    }

    private String query(String sql) throws SQLException {
        try (Connection c = DriverManager.getConnection(env.get("SPRING_DATASOURCE_URL"), env.get("SPRING_DATASOURCE_USERNAME"),
            env.get("SPRING_DATASOURCE_PASSWORD")); Statement s = c.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            rs.next();
            return rs.getString(1);
        }
    }

    @Test
    void createsTheAdministratorOnceAndTheSecondRunIsANoOp() throws Exception {
        Path secret = Files.writeString(dir.resolve("admin.pw"), PASSWORD + "\n");
        String[] args = {"--name", "Initial Admin", "--email", "Initial.Admin@Synkro.test", "--password-file", secret.toString(),
            "--operator", "release-manager@ci", "--correlation-id", "cli-it-1"};

        assertThat(run(args)).isEqualTo(InitialAdminCli.EXIT_SUCCESS);

        assertThat(out.toString(StandardCharsets.UTF_8)).contains("result=created").contains("correlationId=cli-it-1");
        String userId = query("SELECT user_id::text FROM auth_schema.system_user WHERE role = 'ADMIN'");
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("userId=" + userId);
        assertThat(query("SELECT email || '|' || active FROM auth_schema.system_user")).isEqualTo("initial.admin@synkro.test|true");
        assertThat(new BcryptPasswordHasher().matches(PASSWORD, query("SELECT password_hash FROM auth_schema.system_user")))
            .as("the stored hash verifies the password, so a normal login works").isTrue();
        assertThat(query("SELECT operation || '|' || actor_kind || '|' || operator_identity || '|' || correlation_id || '|' "
            + "|| (actor_user_id IS NULL) || '|' || (created_user_id = '" + userId + "'::uuid) FROM auth_schema.user_creation_audit"))
            .isEqualTo("INITIAL_ADMIN_CREATED|OPERATOR|release-manager@ci|cli-it-1|true|true");

        out.reset();
        String hashBefore = query("SELECT password_hash FROM auth_schema.system_user");
        assertThat(run(args)).isEqualTo(InitialAdminCli.EXIT_SUCCESS);

        assertThat(out.toString(StandardCharsets.UTF_8)).contains("result=already_initialized").doesNotContain("userId");
        assertThat(query("SELECT count(*) FROM auth_schema.system_user")).isEqualTo("1");
        assertThat(query("SELECT count(*) FROM auth_schema.user_creation_audit")).isEqualTo("1");
        assertThat(query("SELECT password_hash FROM auth_schema.system_user")).isEqualTo(hashBefore);
        assertThat(out.toString(StandardCharsets.UTF_8) + err.toString(StandardCharsets.UTF_8)).doesNotContain(PASSWORD);
        assertThat(secret).as("the operator's secret file is left for the operator to remove").exists();
    }

    @Test
    void aDatabaseThatCannotBeReachedExitsFourWithoutLeakingTheConnectionSettings() throws Exception {
        env.put("SPRING_DATASOURCE_URL", "jdbc:postgresql://127.0.0.1:1/not_a_real_database");
        env.put("SPRING_DATASOURCE_PASSWORD", "never-printed-db-secret");
        Path secret = Files.writeString(dir.resolve("admin.pw"), PASSWORD);

        int exit = run("--name", "Initial Admin", "--email", "a@synkro.test", "--password-file", secret.toString(),
            "--operator", "release-manager@ci");

        assertThat(exit).isEqualTo(InitialAdminCli.EXIT_DATABASE);
        assertThat(out.toString(StandardCharsets.UTF_8) + err.toString(StandardCharsets.UTF_8))
            .doesNotContain("never-printed-db-secret").doesNotContain("127.0.0.1").doesNotContain(PASSWORD);
    }
}
