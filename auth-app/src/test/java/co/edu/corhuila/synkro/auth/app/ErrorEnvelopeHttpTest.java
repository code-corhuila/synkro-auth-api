package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
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

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every error answers in the common envelope { error, message, details?, traceId }, whichever layer raises it,
 * and the gate still runs first: a request without a valid token never gets past a 401.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(InMemoryAdaptersTestConfig.class)
@ExtendWith(OutputCaptureExtension.class)
class ErrorEnvelopeHttpTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String CORRELATION_ID = "corr-envelope-1";

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        registry.add("JWT_PRIVATE_KEY_FILE", () -> {
            try {
                return TestKeys.writePrivateKeyPem(KEYS, Files.createTempDirectory("error-envelope-test")).toString();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();

    private static String token(String role) {
        return Jwts.builder()
            .subject(UUID.randomUUID().toString())
            .claim("roles", List.of(role))
            .claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300)))
            .signWith(KEYS.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private ResponseEntity<String> call(HttpMethod method, String path, String bearer, MediaType contentType, String... headerPairs) {
        HttpHeaders headers = new HttpHeaders();
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        if (contentType != null) {
            headers.setContentType(contentType);
        }
        headers.set("X-Correlation-Id", CORRELATION_ID);
        for (int i = 0; i < headerPairs.length; i += 2) {
            headers.set(headerPairs[i], headerPairs[i + 1]);
        }
        Object body = contentType == null ? null : "{}";
        return http.exchange("http://localhost:" + port + path, method, new HttpEntity<>(body, headers), String.class);
    }

    private JsonNode assertEnvelope(ResponseEntity<String> response, HttpStatus status, String error) throws Exception {
        assertThat(response.getStatusCode()).isEqualTo(status);
        MediaType type = response.getHeaders().getContentType();
        assertThat(type).isNotNull();
        assertThat(type.isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
        assertThat(type.getCharset()).isEqualTo(StandardCharsets.UTF_8);
        JsonNode body = json.readTree(response.getBody());
        assertThat(body.fieldNames()).toIterable().isSubsetOf("error", "message", "details", "traceId");
        assertThat(body.get("error").asText()).isEqualTo(error);
        assertThat(body.get("message").asText()).isNotBlank();
        assertThat(body.get("traceId").asText()).isEqualTo(CORRELATION_ID);
        assertThat(response.getHeaders().getFirst("X-Correlation-Id")).isEqualTo(CORRELATION_ID);
        return body;
    }

    // ── unknown route: the gate first, then 404 ──────────────────────

    @Test
    void anUnknownRouteWithNoToken_is401() throws Exception {
        assertEnvelope(call(HttpMethod.GET, "/api/v1/auth/anything", null, null), HttpStatus.UNAUTHORIZED, "UNAUTHORIZED");
    }

    @Test
    void anUnknownRouteWithAFakeBearer_is401() throws Exception {
        assertEnvelope(call(HttpMethod.GET, "/api/v1/auth/anything", "not-a-real-token", null), HttpStatus.UNAUTHORIZED, "UNAUTHORIZED");
    }

    @Test
    void anUnknownRouteWithAValidToken_is404InTheEnvelope() throws Exception {
        ResponseEntity<String> response = call(HttpMethod.GET, "/api/v1/auth/anything", token("ADMIN"), null);

        JsonNode body = assertEnvelope(response, HttpStatus.NOT_FOUND, "NOT_FOUND");
        assertThat(response.getBody()).doesNotContain("timestamp").doesNotContain("/api/v1/auth/anything");
        assertThat(body.has("details")).isFalse();
    }

    @Test
    void aMissingIdSegment_isAnUnknownRoute() throws Exception {
        assertEnvelope(call(HttpMethod.GET, "/api/v1/auth/users", token("ADMIN"), null), HttpStatus.NOT_FOUND, "NOT_FOUND");
    }

    // ── wrong method ─────────────────────────────────────────────────

    @Test
    void aWrongMethodOnAKnownRoute_is405InTheEnvelope_withTheAllowHeader() throws Exception {
        ResponseEntity<String> response = call(HttpMethod.GET, "/api/v1/auth/login", token("ADMIN"), null);

        assertEnvelope(response, HttpStatus.METHOD_NOT_ALLOWED, "VALIDATION_ERROR");
        assertThat(response.getHeaders().getAllow()).containsExactly(HttpMethod.POST);
    }

    @Test
    void aWrongMethodOnTheLookup_is405() throws Exception {
        assertEnvelope(call(HttpMethod.POST, "/api/v1/auth/users/" + UUID.randomUUID(), token("ADMIN"), MediaType.APPLICATION_JSON),
            HttpStatus.METHOD_NOT_ALLOWED, "VALIDATION_ERROR");
    }

    @Test
    void aWrongMethodWithNoToken_isStillStoppedByTheGate() throws Exception {
        assertEnvelope(call(HttpMethod.GET, "/api/v1/auth/login", null, null), HttpStatus.UNAUTHORIZED, "UNAUTHORIZED");
    }

    @Test
    void aBodyOfAnUnsupportedType_is415InTheEnvelope() throws Exception {
        assertEnvelope(call(HttpMethod.POST, "/api/v1/auth/login", null, MediaType.TEXT_PLAIN),
            HttpStatus.UNSUPPORTED_MEDIA_TYPE, "VALIDATION_ERROR");
    }

    // ── unexpected failure ───────────────────────────────────────────

    @Test
    void anUnexpectedException_is500InternalError_withAGenericMessageAndNoLeak() throws Exception {
        ResponseEntity<String> response = call(HttpMethod.GET, "/test-probe/boom", token("ADMIN"), null);

        JsonNode body = assertEnvelope(response, HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR");
        assertThat(body.get("message").asText()).isEqualTo("The request could not be completed");
        for (String secret : new String[] {"SECRET-CAUSE", "IllegalStateException", "jdbc:", "SELECT", "system_user", "db.internal",
                "co.edu.corhuila", "java.lang", "at ", "Exception", "stack", "trace\":"}) {
            assertThat(response.getBody()).as("response body must not contain " + secret).doesNotContain(secret);
        }
    }

    @Test
    void theCauseOfAnUnexpectedException_isInTheLog_withTheTraceId(CapturedOutput output) {
        call(HttpMethod.GET, "/test-probe/boom", token("ADMIN"), null, "X-Correlation-Id", "corr-log-scan");

        assertThat(output.getAll())
            .contains("corr-log-scan")
            .contains("IllegalStateException")
            .contains("SECRET-CAUSE");
    }

    @Test
    void anErrorRaisedThroughTheServletApi_isInTheEnvelopeToo_andIsNotMaskedAsA401() throws Exception {
        ResponseEntity<String> response = call(HttpMethod.GET, "/test-probe/send-error", token("ADMIN"), null);

        assertEnvelope(response, HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR");
        assertThat(response.getBody()).doesNotContain("SECRET-CAUSE");
    }

    // ── the correlation id ───────────────────────────────────────────

    @Test
    void whenTheClientSendsNoCorrelationId_theServiceGeneratesOne_forEveryKindOfError() throws Exception {
        String valid = token("ADMIN");
        for (String path : new String[] {"/api/v1/auth/anything", "/test-probe/boom"}) {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(valid);
            ResponseEntity<String> response = http.exchange("http://localhost:" + port + path, HttpMethod.GET,
                new HttpEntity<>(headers), String.class);

            String header = response.getHeaders().getFirst("X-Correlation-Id");
            assertThat(header).isNotBlank();
            assertThat(json.readTree(response.getBody()).get("traceId").asText()).isEqualTo(header);
        }
    }

    @Test
    void malformedJson_isStillTheValidationEnvelope() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Correlation-Id", CORRELATION_ID);
        ResponseEntity<String> response = http.exchange("http://localhost:" + port + "/api/v1/auth/login", HttpMethod.POST,
            new HttpEntity<>("{not json", headers), String.class);

        assertEnvelope(response, HttpStatus.BAD_REQUEST, "VALIDATION_ERROR");
    }
}
