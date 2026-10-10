package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End to end over real HTTP: a real PEM key file on disk, the real Spring wiring, and
 * tokens verified with a public key parsed from PEM, the way a validating service
 * receives JWT_PUBLIC_KEY.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(InMemoryAdaptersTestConfig.class)
class AuthEndpointsHttpTest {

    private static final KeyPair KEY_PAIR = TestKeys.generate(2048);

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("auth-endpoints-test");
        registry.add("JWT_PRIVATE_KEY_FILE", () -> {
            try {
                return TestKeys.writePrivateKeyPem(KEY_PAIR, dir).toString();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private ResponseEntity<String> post(String path, Object body, String... headerPairs) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        for (int i = 0; i < headerPairs.length; i += 2) {
            headers.set(headerPairs[i], headerPairs[i + 1]);
        }
        return http.postForEntity(url(path), new HttpEntity<>(body, headers), String.class);
    }

    private ResponseEntity<String> login(String email, String password) {
        return post("/api/v1/auth/login", Map.of("email", email, "password", password));
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private Claims verified(String accessToken) throws Exception {
        PublicKey publicKey = TestKeys.parsePublicKeyPem(TestKeys.publicKeyPem(KEY_PAIR));
        return Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(accessToken).getPayload();
    }

    // ── login ────────────────────────────────────────────────────────

    @Test
    void login_withValidCredentials_returnsATokenPairVerifiableWithThePublicKey() throws Exception {
        ResponseEntity<String> response = login("admin@synkro.test", "admin-dev-password");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode pair = body(response);
        assertThat(pair.get("tokenType").asText()).isEqualTo("Bearer");
        assertThat(pair.get("expiresIn").asLong()).isEqualTo(3600);
        assertThat(pair.get("refreshToken").asText()).isNotBlank();

        Claims claims = verified(pair.get("accessToken").asText());
        assertThat(UUID.fromString(claims.getSubject())).isNotNull();
        assertThat(claims.get("roles", List.class)).containsExactly("ADMIN");
        assertThat(claims.get("permissions", List.class)).contains("users:manage");
        assertThat(claims.getId()).isNotBlank();
        assertThat(claims.getExpiration().getTime() - claims.getIssuedAt().getTime()).isEqualTo(3_600_000L);
    }

    @Test
    void login_eachSeededRoleGetsItsOwnRoleInTheToken() throws Exception {
        assertThat(verified(body(login("sales@synkro.test", "sales-dev-password")).get("accessToken").asText())
            .get("roles", List.class)).containsExactly("SALESPERSON");
        assertThat(verified(body(login("inventory@synkro.test", "inventory-dev-password")).get("accessToken").asText())
            .get("roles", List.class)).containsExactly("INVENTORY");
    }

    @Test
    void login_responsesAreNotCacheable() {
        ResponseEntity<String> response = login("admin@synkro.test", "admin-dev-password");

        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
    }

    @Test
    void login_wrongPasswordAndUnknownEmail_areIndistinguishable401s() throws Exception {
        ResponseEntity<String> wrongPassword = login("admin@synkro.test", "wrong");
        ResponseEntity<String> unknownEmail = login("ghost@synkro.test", "wrong");

        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknownEmail.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        JsonNode a = body(wrongPassword);
        JsonNode b = body(unknownEmail);
        assertThat(a.get("error").asText()).isEqualTo("UNAUTHORIZED");
        assertThat(a.get("message")).isEqualTo(b.get("message"));
        assertThat(a.get("message").asText().toLowerCase()).doesNotContain("email", "password", "user");
        assertThat(a.get("traceId").asText()).isNotBlank();
    }

    @Test
    void login_isPublic_noAuthorizationHeaderNeeded() {
        // Reaching the use case (401 from bad credentials, not from the security filter)
        // proves the route was permitted without a Bearer token.
        ResponseEntity<String> response = login("ghost@synkro.test", "x");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).contains("Invalid credentials");
    }

    @Test
    void login_missingFields_is400ValidationErrorWithDetails() throws Exception {
        ResponseEntity<String> response = post("/api/v1/auth/login", Map.of("email", "admin@synkro.test"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode error = body(response);
        assertThat(error.get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(error.get("details").get(0).get("field").asText()).isEqualTo("password");
    }

    @Test
    void login_malformedJson_is400ValidationError() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> response = http.postForEntity(
            url("/api/v1/auth/login"), new HttpEntity<>("{not json", headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(response).get("error").asText()).isEqualTo("VALIDATION_ERROR");
    }

    @Test
    void errors_useTheCallersCorrelationIdAsTraceId_andEchoItInTheResponse() throws Exception {
        ResponseEntity<String> response = post("/api/v1/auth/login",
            Map.of("email", "ghost@synkro.test", "password", "x"), "X-Correlation-Id", "corr-123");

        assertThat(body(response).get("traceId").asText()).isEqualTo("corr-123");
        assertThat(response.getHeaders().getFirst("X-Correlation-Id")).isEqualTo("corr-123");
    }

    // ── refresh ──────────────────────────────────────────────────────

    @Test
    void refresh_rotatesTheToken_andReplayingTheOldOneIs401() throws Exception {
        JsonNode first = body(login("sales@synkro.test", "sales-dev-password"));
        String oldRefresh = first.get("refreshToken").asText();

        ResponseEntity<String> rotated = post("/api/v1/auth/refresh", Map.of("refreshToken", oldRefresh));
        assertThat(rotated.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode second = body(rotated);
        assertThat(second.get("refreshToken").asText()).isNotEqualTo(oldRefresh);
        assertThat(second.get("tokenType").asText()).isEqualTo("Bearer");
        assertThat(verified(second.get("accessToken").asText()).get("roles", List.class))
            .containsExactly("SALESPERSON");

        ResponseEntity<String> replay = post("/api/v1/auth/refresh", Map.of("refreshToken", oldRefresh));
        assertThat(replay.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(body(replay).get("error").asText()).isEqualTo("UNAUTHORIZED");

        // The rotated token is still good: only the used one was burned.
        ResponseEntity<String> next = post("/api/v1/auth/refresh", Map.of("refreshToken", second.get("refreshToken").asText()));
        assertThat(next.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void refresh_unknownToken_is401() {
        ResponseEntity<String> response = post("/api/v1/auth/refresh", Map.of("refreshToken", "never-issued"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void refresh_missingToken_is400ValidationError() throws Exception {
        ResponseEntity<String> response = post("/api/v1/auth/refresh", Map.of());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(response).get("details").get(0).get("field").asText()).isEqualTo("refreshToken");
    }

    @Test
    void refresh_accessTokenIsNotAcceptedAsARefreshToken() throws Exception {
        String access = body(login("admin@synkro.test", "admin-dev-password")).get("accessToken").asText();

        ResponseEntity<String> response = post("/api/v1/auth/refresh", Map.of("refreshToken", access));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
