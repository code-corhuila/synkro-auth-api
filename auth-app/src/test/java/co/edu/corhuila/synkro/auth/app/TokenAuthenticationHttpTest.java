package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.charset.StandardCharsets;
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
 * The real filter chain over real HTTP, against the test-only routes of {@link ProbeController}.
 * Tokens are minted here with the same key the service signs with, so a rejected token is
 * rejected for what is wrong with it and not because the key differs.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TokenAuthenticationHttpTest {

    private static final KeyPair SERVICE_KEYS = TestKeys.generate(2048);
    private static final String UNAUTHORIZED_MESSAGE = "Missing or invalid authentication token";

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("token-authentication-test");
        Path key = TestKeys.writePrivateKeyPem(SERVICE_KEYS, dir);
        registry.add("JWT_PRIVATE_KEY_FILE", key::toString);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private ResponseEntity<String> get(String path, String... headerPairs) {
        HttpHeaders headers = new HttpHeaders();
        for (int i = 0; i < headerPairs.length; i += 2) {
            headers.set(headerPairs[i], headerPairs[i + 1]);
        }
        return http.exchange(url(path), HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }

    private ResponseEntity<String> getWithBearer(String path, String token, String... extraHeaders) {
        String[] headers = new String[extraHeaders.length + 2];
        headers[0] = "Authorization";
        headers[1] = "Bearer " + token;
        System.arraycopy(extraHeaders, 0, headers, 2, extraHeaders.length);
        return get(path, headers);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private static String token(KeyPair signer, String role, Instant expiresAt, String... permissions) {
        return Jwts.builder()
            .subject(UUID.randomUUID().toString())
            .claim("roles", List.of(role))
            .claim("permissions", List.of(permissions))
            .expiration(Date.from(expiresAt))
            .signWith(signer.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private static String valid(String role) {
        return token(SERVICE_KEYS, role, Instant.now().plusSeconds(300));
    }

    private String loginAndGet(String field) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> response = http.postForEntity(url("/api/v1/auth/login"),
            new HttpEntity<>(Map.of("email", "admin@synkro.test", "password", "admin-dev-password"), headers), String.class);
        return body(response).get(field).asText();
    }

    private void assertUnauthorizedEnvelope(ResponseEntity<String> response) throws Exception {
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        JsonNode body = body(response);
        assertThat(body.get("error").asText()).isEqualTo("UNAUTHORIZED");
        assertThat(body.get("message").asText()).isEqualTo(UNAUTHORIZED_MESSAGE);
        assertThat(body.get("traceId").asText()).isNotBlank();
    }

    // ── 401: every way of not being authenticated ────────────────────

    @Test
    void noAuthorizationHeader_is401() throws Exception {
        assertUnauthorizedEnvelope(get("/test-probe/whoami"));
    }

    @Test
    void aFakeBearer_is401() throws Exception {
        assertUnauthorizedEnvelope(getWithBearer("/test-probe/whoami", "not-a-real-token"));
    }

    @Test
    void aMalformedJwt_is401() throws Exception {
        assertUnauthorizedEnvelope(getWithBearer("/test-probe/whoami", "aaa.bbb.ccc"));
    }

    @Test
    void anAuthorizationHeaderThatIsNotBearer_is401() throws Exception {
        assertUnauthorizedEnvelope(get("/test-probe/whoami", "Authorization", "Basic YWRtaW46YWRtaW4="));
    }

    @Test
    void anExpiredToken_is401() throws Exception {
        String expired = token(SERVICE_KEYS, "ADMIN", Instant.now().minusSeconds(3600));

        assertUnauthorizedEnvelope(getWithBearer("/test-probe/whoami", expired));
    }

    @Test
    void aTokenSignedWithAnotherKey_is401() throws Exception {
        String forged = token(TestKeys.generate(2048), "ADMIN", Instant.now().plusSeconds(300));

        assertUnauthorizedEnvelope(getWithBearer("/test-probe/whoami", forged));
    }

    @Test
    void anOpaqueRefreshToken_is401() throws Exception {
        assertUnauthorizedEnvelope(getWithBearer("/test-probe/whoami", loginAndGet("refreshToken")));
    }

    // ── 200 and 403: the role decision ───────────────────────────────

    @Test
    void aValidTokenWithTheRequiredRole_is200_withTheClaimsOfTheToken() throws Exception {
        ResponseEntity<String> response = getWithBearer("/test-probe/admin-only", loginAndGet("accessToken"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode body = body(response);
        assertThat(body.get("roles").get(0).asText()).isEqualTo("ADMIN");
        assertThat(body.get("permissions").toString()).contains("users:manage");
    }

    @Test
    void aValidTokenWithAnotherRole_is403Forbidden_namingTheRoleAndTheOperation() throws Exception {
        ResponseEntity<String> response = getWithBearer("/test-probe/admin-only", valid("INVENTORY"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        JsonNode body = body(response);
        assertThat(body.get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(body.get("message").asText()).isEqualTo("Role INVENTORY is not authorized to read the admin probe");
    }

    @Test
    void aServiceTokenIsRefusedByAnOperationOnlyPeopleMayDo() throws Exception {
        ResponseEntity<String> response = getWithBearer("/test-probe/people-only", valid("SERVICE"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("message").asText()).isEqualTo("Role SERVICE is not authorized to read the people probe");
    }

    @Test
    void anAccessDeniedRaisedByTheFramework_isThe403Envelope_notAnEmptyBody() throws Exception {
        ResponseEntity<String> response = getWithBearer("/test-probe/framework-denied", valid("ADMIN"), "X-Correlation-Id", "corr-denied");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        JsonNode body = body(response);
        assertThat(body.get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(body.get("traceId").asText()).isEqualTo("corr-denied");
    }

    // ── X-User-* headers are never an identity ───────────────────────

    @Test
    void xUserRoleHeaderDoesNotChangeTheRoleOfAValidToken() throws Exception {
        String inventory = valid("INVENTORY");

        ResponseEntity<String> whoami = getWithBearer("/test-probe/whoami", inventory, "X-User-Role", "ADMIN", "X-User-Id", "someone-else");
        ResponseEntity<String> adminOnly = getWithBearer("/test-probe/admin-only", inventory, "X-User-Role", "ADMIN");

        assertThat(body(whoami).get("roles").get(0).asText()).isEqualTo("INVENTORY");
        assertThat(body(whoami).get("subject").asText()).isNotEqualTo("someone-else");
        assertThat(adminOnly.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void xUserHeadersWithNoToken_are401() throws Exception {
        assertUnauthorizedEnvelope(get("/test-probe/admin-only", "X-User-Role", "ADMIN", "X-User-Id", "u-1"));
    }

    // ── the envelope: traceId, correlation header, charset ───────────

    @Test
    void the401CarriesTheRequestsCorrelationIdAsTraceId_andEchoesTheHeader() throws Exception {
        ResponseEntity<String> response = get("/test-probe/whoami", "X-Correlation-Id", "corr-401");

        assertThat(body(response).get("traceId").asText()).isEqualTo("corr-401");
        assertThat(response.getHeaders().getFirst("X-Correlation-Id")).isEqualTo("corr-401");
    }

    @Test
    void the403CarriesTheRequestsCorrelationIdAsTraceId_andEchoesTheHeader() throws Exception {
        ResponseEntity<String> response = getWithBearer("/test-probe/admin-only", valid("SALESPERSON"), "X-Correlation-Id", "corr-403");

        assertThat(body(response).get("traceId").asText()).isEqualTo("corr-403");
        assertThat(response.getHeaders().getFirst("X-Correlation-Id")).isEqualTo("corr-403");
    }

    @Test
    void whenTheClientSendsNoCorrelationId_theServiceGeneratesOne_andTheBodyAndHeaderAgree() throws Exception {
        ResponseEntity<String> unauthorized = get("/test-probe/whoami");
        ResponseEntity<String> forbidden = getWithBearer("/test-probe/admin-only", valid("INVENTORY"));

        for (ResponseEntity<String> response : List.of(unauthorized, forbidden)) {
            String header = response.getHeaders().getFirst("X-Correlation-Id");
            assertThat(header).isNotBlank();
            assertThat(body(response).get("traceId").asText()).isEqualTo(header);
        }
    }

    @Test
    void the401And403Bodies_areUtf8Json() {
        List<ResponseEntity<String>> responses = List.of(
            get("/test-probe/whoami"),
            getWithBearer("/test-probe/admin-only", valid("INVENTORY")));

        for (ResponseEntity<String> response : responses) {
            MediaType type = response.getHeaders().getContentType();
            assertThat(type).isNotNull();
            assertThat(type.isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
            assertThat(type.getCharset()).isEqualTo(StandardCharsets.UTF_8);
        }
    }

    // ── public routes stay public; the gate does not mask real errors ─

    @Test
    void healthLoginAndRefresh_workWithNoToken() throws Exception {
        assertThat(get("/health").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(loginAndGet("accessToken")).isNotBlank();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<String> refreshed = http.postForEntity(url("/api/v1/auth/refresh"),
            new HttpEntity<>(Map.of("refreshToken", loginAndGet("refreshToken")), headers), String.class);
        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void anExpiredBearerOnAPublicRoute_doesNotBlockIt() throws Exception {
        String expired = token(SERVICE_KEYS, "ADMIN", Instant.now().minusSeconds(3600));
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(expired);

        ResponseEntity<String> refreshed = http.postForEntity(url("/api/v1/auth/refresh"),
            new HttpEntity<>(Map.of("refreshToken", loginAndGet("refreshToken")), headers), String.class);

        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(get("/health", "Authorization", "Bearer " + expired).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void anUnknownRouteBehindAValidToken_keepsItsReal404() throws Exception {
        ResponseEntity<String> response = getWithBearer("/api/v1/auth/anything", valid("ADMIN"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void anUnknownRouteWithNoToken_is401() throws Exception {
        assertUnauthorizedEnvelope(get("/api/v1/auth/anything"));
    }

    @Test
    void theRemovedPlaceholderRoute_isGone() throws Exception {
        ResponseEntity<String> response = getWithBearer("/api/v1/users/anything", valid("ADMIN"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
