package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.UUID;

/**
 * Wires a test context to the database named by TEST_DATABASE_URL, connecting as auth_app
 * like the service does. The schema comes from synkro-auth-db; rows are never deleted, so
 * every test creates its own users with fresh emails.
 */
final class DatabaseTestSupport {

    static final String URL_VARIABLE = "TEST_DATABASE_URL";

    private DatabaseTestSupport() {}

    static void registerDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> System.getenv(URL_VARIABLE));
        registry.add("spring.datasource.username", DatabaseTestSupport::user);
        registry.add("spring.datasource.password", () -> System.getenv("TEST_DATABASE_PASSWORD"));
    }

    static void registerSigningKey(DynamicPropertyRegistry registry, KeyPair keys, String dirName) throws Exception {
        Path dir = Files.createTempDirectory(dirName);
        Path key = TestKeys.writePrivateKeyPem(keys, dir);
        registry.add("JWT_PRIVATE_KEY_FILE", key::toString);
    }

    static JdbcTemplate jdbc() {
        return new JdbcTemplate(new DriverManagerDataSource(
            System.getenv(URL_VARIABLE), user(), System.getenv("TEST_DATABASE_PASSWORD")));
    }

    static String insertUser(JdbcTemplate jdbc, String email, String password, String role, boolean active) {
        return jdbc.queryForObject(
            "INSERT INTO auth_schema.system_user (name, email, password_hash, role, active) "
                + "VALUES (?, ?, ?, ?, ?) RETURNING user_id::text",
            String.class, "Test User", email, new BcryptPasswordHasher().hash(password), role, active);
    }

    static String uniqueEmail() {
        return "it-" + UUID.randomUUID() + "@synkro.test";
    }

    private static String user() {
        return System.getenv().getOrDefault("TEST_DATABASE_USER", "auth_app");
    }
}
