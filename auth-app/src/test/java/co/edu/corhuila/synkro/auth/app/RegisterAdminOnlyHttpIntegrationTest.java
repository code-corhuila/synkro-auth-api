package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * register is an operation of a human ADMIN: who is calling, what that caller may do, and what the
 * database holds afterwards, over real HTTP against the real PostgreSQL schema.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class RegisterAdminOnlyHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final KeyPair OTHER_KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "register-admin-only-http-test");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();

    // ── helpers ──────────────────────────────────────────────────────

    private static String newKey() {
        return "it-key-" + UUID.randomUUID();
    }

    private static Map<String, Object> request(String email, String role) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "Ana Perez");
        body.put("email", email);
        body.put("password", PASSWORD);
        body.put("role", role);
        return body;
    }

    private ResponseEntity<String> register(Map<String, Object> body, String key, String authorization) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Idempotency-Key", key);
        if (authorization != null) {
            headers.set("Authorization", authorization);
        }
        return http.exchange("http://localhost:" + port + "/api/v1/auth/register", HttpMethod.POST,
            new HttpEntity<>(body, headers), String.class);
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String tokenFor(KeyPair keys, String subject, String role, Instant expiresAt) {
        return Jwts.builder()
            .subject(subject)
            .claim("roles", List.of(role))
            .claim("permissions", List.of())
            .expiration(Date.from(expiresAt))
            .signWith(keys.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private String seededUser(String role) {
        return DatabaseTestSupport.insertUser(jdbc, DatabaseTestSupport.uniqueEmail(), PASSWORD, role, true);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private int count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema." + table, Integer.class);
    }

    /** Rows that registering could write; the audit table joins once it exists (AUTH-REG-04). */
    private record Rows(int users, int keys) {}

    private Rows rows() {
        return new Rows(count("system_user"), count("idempotency_key"));
    }

    // ── AUTH-REG-01: authentication required ─────────────────────────

    @Test
    @Tag("AUTH-REG-01")
    void case1_aMissingAuthorizationHeader_is401_andWritesNothing() throws Exception {
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(body(response).get("error").asText()).isEqualTo("UNAUTHORIZED");
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-01")
    void case2_aMalformedToken_is401_andWritesNothing() {
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), bearer("not.a.jwt"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-01")
    void case3_anExpiredToken_is401_andWritesNothing() {
        String expired = tokenFor(KEYS, seededUser("ADMIN"), "ADMIN", Instant.now().minusSeconds(3600));
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), bearer(expired));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(rows()).isEqualTo(before);
    }

    @Test
    @Tag("AUTH-REG-01")
    void case4_aTokenWithAnInvalidSignature_is401_andWritesNothing() {
        String forged = tokenFor(OTHER_KEYS, seededUser("ADMIN"), "ADMIN", Instant.now().plusSeconds(300));
        Rows before = rows();

        ResponseEntity<String> response = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey(), bearer(forged));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(rows()).isEqualTo(before);
    }
}
