package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * POST /api/v1/auth/users/search over the real filter chain, against the three fixed
 * FakeUserRepository identities (HU-AUTH-18, issue #297). No real pagination/ILIKE semantics
 * are exercised here: those belong to JdbcUserRepositorySearchIntegrationTest (AUTH-SEARCH-04).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(InMemoryAdaptersTestConfig.class)
class SearchUsersHttpTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("search-users-http-test");
        Path key = TestKeys.writePrivateKeyPem(KEYS, dir);
        registry.add("JWT_PRIVATE_KEY_FILE", key::toString);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();

    private static String tokenFor(String role) {
        return Jwts.builder()
            .subject(UUID.randomUUID().toString())
            .claim("roles", List.of(role))
            .claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300)))
            .signWith(KEYS.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private ResponseEntity<String> search(String token, Map<String, Object> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return http.exchange("http://localhost:" + port + "/api/v1/auth/users/search",
            HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    // ── 401/403 ──────────────────────────────────────────────────────

    @Test
    @Tag("AUTH-SEARCH-02")
    void noToken_is401() {
        assertThat(search(null, Map.of()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    @Tag("AUTH-SEARCH-02")
    void anyNonAdminCaller_is403(String role) throws Exception {
        ResponseEntity<String> response = search(tokenFor(role), Map.of());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
    }

    @Test
    @Tag("AUTH-SEARCH-02")
    void aServiceToken_is403() throws Exception {
        assertThat(search(tokenFor("SERVICE"), Map.of()).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── 400 ──────────────────────────────────────────────────────────

    @Test
    @Tag("AUTH-SEARCH-02")
    void anInvalidRole_is400ValidationError() throws Exception {
        ResponseEntity<String> response = search(tokenFor("ADMIN"), Map.of("role", "OWNER"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode error = body(response);
        assertThat(error.get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(error.get("details").get(0).get("field").asText()).isEqualTo("role");
    }

    @Test
    void unexpectedFieldsAndFractionalPagesAreRejected() {
        assertThat(search(tokenFor("ADMIN"), Map.of("unexpected", true)).getStatusCode())
            .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(search(tokenFor("ADMIN"), Map.of("page", 1.5)).getStatusCode())
            .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 101})
    @Tag("AUTH-SEARCH-02")
    void anOutOfRangeLimit_is400ValidationError(int limit) throws Exception {
        ResponseEntity<String> response = search(tokenFor("ADMIN"), Map.of("limit", limit));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(response).get("details").get(0).get("field").asText()).isEqualTo("limit");
    }

    // ── 200: an ADMIN gets a bounded, filtered page ───────────────────

    @Test
    @Tag("AUTH-SEARCH-01")
    void anAdmin_withNoFilters_getsEveryFixedUserPaginated() throws Exception {
        ResponseEntity<String> response = search(tokenFor("ADMIN"), Map.of());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode result = body(response);
        assertThat(result.get("meta").get("total").asInt()).isEqualTo(3);
        assertThat(result.get("meta").get("page").asInt()).isEqualTo(1);
        assertThat(result.get("meta").get("limit").asInt()).isEqualTo(20);
        assertThat(result.get("data")).hasSize(3);
        assertThat(result.toString()).doesNotContainIgnoringCase("passwordHash").doesNotContain("$2");
    }

    @Test
    @Tag("AUTH-SEARCH-01")
    void qMatchesNameOrEmail_caseInsensitively() throws Exception {
        ResponseEntity<String> response = search(tokenFor("ADMIN"), Map.of("q", "INVENTORY"));

        JsonNode data = body(response).get("data");
        assertThat(data).hasSize(1);
        assertThat(data.get(0).get("email").asText()).isEqualTo("inventory@synkro.test");
    }

    @Test
    @Tag("AUTH-SEARCH-01")
    void roleFilter_narrowsToExactlyThatRole() throws Exception {
        ResponseEntity<String> response = search(tokenFor("ADMIN"), Map.of("role", "SALESPERSON"));

        JsonNode data = body(response).get("data");
        assertThat(data).hasSize(1);
        assertThat(data.get(0).get("role").asText()).isEqualTo("SALESPERSON");
    }

    @Test
    @Tag("AUTH-SEARCH-01")
    void qAndRoleCombine_asAnAndFilter_noMatchIsAnEmptyPage_notAnError() throws Exception {
        ResponseEntity<String> response = search(tokenFor("ADMIN"), Map.of("q", "inventory", "role", "ADMIN"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode result = body(response);
        assertThat(result.get("data")).isEmpty();
        assertThat(result.get("meta").get("total").asInt()).isZero();
    }

    @Test
    @Tag("AUTH-SEARCH-01")
    void pagination_boundedLimitSplitsTheFixedUsersAcrossPages_withNoOverlap() throws Exception {
        JsonNode page1 = body(search(tokenFor("ADMIN"), Map.of("limit", 1, "page", 1)));
        JsonNode page2 = body(search(tokenFor("ADMIN"), Map.of("limit", 1, "page", 2)));

        assertThat(page1.get("data")).hasSize(1);
        assertThat(page2.get("data")).hasSize(1);
        assertThat(page1.get("data").get(0).get("userId").asText())
            .isNotEqualTo(page2.get("data").get(0).get("userId").asText());
        assertThat(page1.get("meta").get("totalPages").asInt()).isEqualTo(3);
    }
}
