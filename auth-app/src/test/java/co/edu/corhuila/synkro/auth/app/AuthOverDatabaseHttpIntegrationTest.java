package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** login and refresh over real HTTP against the real PostgreSQL schema, with no fakes. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class AuthOverDatabaseHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "auth-database-http-test");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();

    private ResponseEntity<String> post(String path, Map<String, String> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return http.postForEntity("http://localhost:" + port + path, new HttpEntity<>(body, headers), String.class);
    }

    private ResponseEntity<String> login(String email, String password) {
        return post("/api/v1/auth/login", Map.of("email", email, "password", password));
    }

    private ResponseEntity<String> refresh(String refreshToken) {
        return post("/api/v1/auth/refresh", Map.of("refreshToken", refreshToken));
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        Iterator<String> iterator = node.fieldNames();
        iterator.forEachRemaining(names::add);
        return names;
    }

    private int rowsWithToken(String token) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE token = ?", Integer.class, token);
    }

    private boolean activeOf(String token) {
        return jdbc.queryForObject("SELECT active FROM auth_schema.refresh_token WHERE token = ?", Boolean.class, token);
    }

    @Test
    void login_withAStoredUser_returnsARealRs256Pair_andStoresOnlyTheHashOfTheRefreshToken() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String userId = DatabaseTestSupport.insertUser(jdbc, email, PASSWORD, "SALESPERSON", true);

        ResponseEntity<String> response = login(email, PASSWORD);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode pair = body(response);
        Claims claims = Jwts.parser().verifyWith(TestKeys.parsePublicKeyPem(TestKeys.publicKeyPem(KEYS))).build()
            .parseSignedClaims(pair.get("accessToken").asText()).getPayload();
        assertThat(claims.getSubject()).isEqualTo(userId);
        assertThat(claims.get("roles", List.class)).containsExactly("SALESPERSON");

        String refreshToken = pair.get("refreshToken").asText();
        String hash = new Sha256HashFunction().hash(refreshToken);
        assertThat(rowsWithToken(refreshToken)).as("rows holding the plaintext token").isZero();
        assertThat(rowsWithToken(hash)).as("rows holding its hash").isEqualTo(1);
        assertThat(activeOf(hash)).isTrue();
        Double secondsLeft = jdbc.queryForObject(
            "SELECT extract(epoch FROM expiration_date - now())::float8 FROM auth_schema.refresh_token WHERE token = ?",
            Double.class, hash);
        // The expiry is computed by the service clock and read back against the database clock.
        assertThat(secondsLeft).isBetween(7 * 86_400.0 - 120, 7 * 86_400.0 + 120);
    }

    @Test
    void login_ofADeactivatedUser_andOfAWrongPassword_areTheSame401() throws Exception {
        String active = DatabaseTestSupport.uniqueEmail();
        DatabaseTestSupport.insertUser(jdbc, active, PASSWORD, "ADMIN", true);
        String deactivated = DatabaseTestSupport.uniqueEmail();
        DatabaseTestSupport.insertUser(jdbc, deactivated, PASSWORD, "ADMIN", false);

        ResponseEntity<String> wrongPassword = login(active, "wrong-" + PASSWORD);
        ResponseEntity<String> inactive = login(deactivated, PASSWORD);

        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(inactive.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        JsonNode a = body(wrongPassword);
        JsonNode b = body(inactive);
        assertThat(b.get("error")).isEqualTo(a.get("error"));
        assertThat(b.get("message")).isEqualTo(a.get("message"));
        assertThat(fieldNames(b)).isEqualTo(fieldNames(a));
    }

    @Test
    void refresh_rotatesOverTheDatabase_andTheOldTokenIsRejected() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        DatabaseTestSupport.insertUser(jdbc, email, PASSWORD, "INVENTORY", true);
        String oldToken = body(login(email, PASSWORD)).get("refreshToken").asText();

        ResponseEntity<String> first = refresh(oldToken);
        ResponseEntity<String> second = refresh(oldToken);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        Sha256HashFunction sha = new Sha256HashFunction();
        assertThat(activeOf(sha.hash(oldToken))).isFalse();
        assertThat(activeOf(sha.hash(body(first).get("refreshToken").asText()))).isTrue();
    }
}
