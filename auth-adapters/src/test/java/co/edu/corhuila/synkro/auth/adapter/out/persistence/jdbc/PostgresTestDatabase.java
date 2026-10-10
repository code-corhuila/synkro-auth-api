package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

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

    static String insertUser(JdbcTemplate jdbc, String role, boolean active) {
        return jdbc.queryForObject(
            "INSERT INTO auth_schema.system_user (name, email, password_hash, role, active) "
                + "VALUES (?, ?, ?, ?, ?) RETURNING user_id::text",
            String.class, "Test User", "it-" + UUID.randomUUID() + "@synkro.test", "not-a-real-hash", role, active);
    }
}
