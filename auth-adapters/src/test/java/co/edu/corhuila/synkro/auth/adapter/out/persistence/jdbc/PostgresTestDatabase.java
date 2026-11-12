package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.UUID;

/**
 * Connects the way the service does: as auth_app, whose grants (no DELETE) the tests rely on.
 * The schema is built by synkro-auth-db; nothing here creates or drops it. Rows are never
 * deleted, so every test uses fresh ids and emails instead of cleaning up.
 */
final class PostgresTestDatabase {

    static final String URL_VARIABLE = "TEST_DATABASE_URL";

    private PostgresTestDatabase() {}

    static JdbcTemplate jdbcTemplate() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
            System.getenv(URL_VARIABLE),
            System.getenv().getOrDefault("TEST_DATABASE_USER", "auth_app"),
            System.getenv("TEST_DATABASE_PASSWORD"));
        return new JdbcTemplate(dataSource);
    }

    static DataSourceTransactionManager transactionManager(JdbcTemplate jdbc) {
        return new DataSourceTransactionManager(jdbc.getDataSource());
    }

    static TransactionTemplate transactions(JdbcTemplate jdbc) {
        return new TransactionTemplate(transactionManager(jdbc));
    }

    private static final String BCRYPT_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final java.security.SecureRandom RANDOM = new java.security.SecureRandom();

    /**
     * A string with the shape of a bcrypt hash ({@code $2a$12$} and 53 characters). The receipt table refuses anything
     * else, so the tests that hand a hash straight to the store need one. It is random and verifies no password.
     */
    static String bcryptShaped() {
        StringBuilder hash = new StringBuilder("$2a$12$");
        for (int i = 0; i < 53; i++) {
            hash.append(BCRYPT_ALPHABET.charAt(RANDOM.nextInt(BCRYPT_ALPHABET.length())));
        }
        return hash.toString();
    }

    static String uniqueEmail() {
        return "it-" + UUID.randomUUID() + "@synkro.test";
    }

    static String insertUser(JdbcTemplate jdbc, String name, String email, String passwordHash, String role, boolean active) {
        return jdbc.queryForObject(
            "INSERT INTO auth_schema.system_user (name, email, password_hash, role, active) "
                + "VALUES (?, ?, ?, ?, ?) RETURNING user_id::text",
            String.class, name, email, passwordHash, role, active);
    }

    static String insertUser(JdbcTemplate jdbc, String role, boolean active) {
        return insertUser(jdbc, "Test User", uniqueEmail(), "not-a-real-hash", role, active);
    }
}
