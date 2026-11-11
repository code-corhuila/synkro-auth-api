package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * POST /api/v1/auth/users/{id}/password-reset over the real filter chain, against the three fixed FakeUserRepository
 * identities and a store that only remembers what it was handed (HU-AUTH-19, ADR-021). What the unit does to rows,
 * and the login and refresh effects, belong to ResetPasswordHttpIntegrationTest and the JDBC tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(InMemoryAdaptersTestConfig.class)
class ResetPasswordHttpTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String ADMIN_ID = "00000000-0000-0000-0000-000000000001";
    private static final String SALES_ID = "00000000-0000-0000-0000-000000000002";
    private static final String INVENTORY_ID = "00000000-0000-0000-0000-000000000003";
    private static final String NEW_PASSWORD = "brand-new-passphrase";

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("reset-password-http-test");
        Path key = TestKeys.writePrivateKeyPem(KEYS, dir);
        registry.add("JWT_PRIVATE_KEY_FILE", key::toString);
    }

    @LocalServerPort
    int port;

    @Autowired
    FakePasswordResetStore store;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();

    @BeforeEach
    void forgetEarlierCalls() {
        store.calls.clear();
    }

    private static String tokenFor(String subject, String... roles) {
        return Jwts.builder()
            .subject(subject)
            .claim("roles", List.of(roles))
            .claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300)))
            .signWith(KEYS.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private static Map<String, Object> passwordBody(String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("newPassword", password);
        body.put("confirmPassword", password);
        return body;
    }

    private ResponseEntity<String> reset(String token, String targetId, String key, Object body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        if (key != null) {
            headers.set("Idempotency-Key", key);
        }
        headers.set("X-Correlation-Id", "corr-reset-http");
        return http.exchange("http://localhost:" + port + "/api/v1/auth/users/" + targetId + "/password-reset",
            HttpMethod.POST, new HttpEntity<>(body, headers), String.class);
    }

    private ResponseEntity<String> resetAsAdmin(String targetId, String key, Object body) {
        return reset(tokenFor(ADMIN_ID, "ADMIN"), targetId, key, body);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    // ── 401 / 403 ────────────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    void forbiddenCallerIsRejectedBeforeAMissingBody(String role) throws Exception {
        var response = reset(tokenFor(SALES_ID, role), SALES_ID, "reset-auth-first-empty", null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(store.calls).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    void forbiddenCallerIsRejectedBeforeMalformedJson(String role) throws Exception {
        var response = reset(tokenFor(SALES_ID, role), SALES_ID, "reset-auth-first-json", "{");
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(store.calls).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    void forbiddenCallerIsRejectedBeforeUnsupportedContentType(String role) throws Exception {
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        headers.setBearerAuth(tokenFor(SALES_ID, role));
        headers.set("Idempotency-Key", "reset-auth-first-media");
        var response = http.exchange("http://localhost:" + port + "/api/v1/auth/users/" + SALES_ID + "/password-reset",
            HttpMethod.POST, new HttpEntity<>("{}", headers), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(store.calls).isEmpty();
    }

    @Test
    void anAuthorizedCallerStillReceives415ForUnsupportedContentType() {
        var headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_PLAIN);
        headers.setBearerAuth(tokenFor(ADMIN_ID, "ADMIN"));
        headers.set("Idempotency-Key", "reset-admin-media");
        var response = http.exchange("http://localhost:" + port + "/api/v1/auth/users/" + SALES_ID + "/password-reset",
            HttpMethod.POST, new HttpEntity<>("{}", headers), String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        assertThat(store.calls).isEmpty();
    }

    @Test
    void anAuthorizedCallerStillReceives415ForAnInvalidMediaType() throws Exception {
        var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create("http://localhost:" + port
                + "/api/v1/auth/users/" + SALES_ID + "/password-reset"))
            .header("Authorization", "Bearer " + tokenFor(ADMIN_ID, "ADMIN"))
            .header("Content-Type", "not-a-media-type")
            .header("Idempotency-Key", "reset-invalid-media")
            .POST(java.net.http.HttpRequest.BodyPublishers.ofString("{}"))
            .build();
        var response = java.net.http.HttpClient.newHttpClient().send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(415);
        assertThat(store.calls).isEmpty();
    }

    @Test
    void anAuthorizedCallerWithNoBodyOrContentTypeStillReceives400() throws Exception {
        var request = java.net.http.HttpRequest.newBuilder(java.net.URI.create("http://localhost:" + port
                + "/api/v1/auth/users/" + SALES_ID + "/password-reset"))
            .header("Authorization", "Bearer " + tokenFor(ADMIN_ID, "ADMIN"))
            .header("Idempotency-Key", "reset-empty-media")
            .POST(java.net.http.HttpRequest.BodyPublishers.noBody())
            .build();
        var response = java.net.http.HttpClient.newHttpClient().send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(store.calls).isEmpty();
    }

    @Test
    @Tag("AUTH-RESET-04")
    void noToken_is401_andNothingIsHandedToTheStore() {
        ResponseEntity<String> response = reset(null, SALES_ID, "reset-key-0001", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(store.calls).isEmpty();
    }

    @Test
    void anInvalidToken_is401() {
        ResponseEntity<String> response = reset("not.a.jwt", SALES_ID, "reset-key-0001", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(store.calls).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    @Tag("AUTH-RESET-04")
    void anyOtherRole_is403_calledDirectly(String role) throws Exception {
        ResponseEntity<String> response = reset(tokenFor(SALES_ID, role), INVENTORY_ID, "reset-key-0001", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(store.calls).isEmpty();
    }

    @Test
    void aWellFormedAdminTokenForAnAccountThatDoesNotExist_is403() {
        ResponseEntity<String> response = reset(tokenFor(UUID.randomUUID().toString(), "ADMIN"), SALES_ID,
            "reset-key-0001", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(store.calls).isEmpty();
    }

    // ── success ──────────────────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-05")
    void anAdminResetsASalesperson_200WithTheUserAndTheInstant_neverTheSecret() throws Exception {
        ResponseEntity<String> response = resetAsAdmin(SALES_ID, "reset-key-0001", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        JsonNode result = body(response);
        assertThat(result.fieldNames()).toIterable().containsExactlyInAnyOrder("userId", "passwordResetAt");
        assertThat(result.get("userId").asText()).isEqualTo(SALES_ID);
        assertThat(Instant.parse(result.get("passwordResetAt").asText())).isBeforeOrEqualTo(Instant.now());
        assertThat(response.getBody()).doesNotContain(NEW_PASSWORD).doesNotContain("$2");
    }

    @Test
    void anAdminResetsAnInventoryUser() {
        assertThat(resetAsAdmin(INVENTORY_ID, "reset-key-0002", passwordBody(NEW_PASSWORD)).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    @Tag("AUTH-RESET-05")
    void theStoreIsHandedTheVerifiedActor_theKey_theCorrelationId_andAHashNotThePassword() {
        resetAsAdmin(SALES_ID, "reset-key-0003", passwordBody(NEW_PASSWORD));

        assertThat(store.calls).singleElement().satisfies(call -> {
            assertThat(call.idempotencyKey()).isEqualTo("reset-key-0003");
            assertThat(call.targetUserId()).isEqualTo(SALES_ID);
            assertThat(call.attribution().actorUserId()).isEqualTo(ADMIN_ID);
            assertThat(call.attribution().correlationId()).isEqualTo("corr-reset-http");
            assertThat(call.newPasswordHash()).startsWith("$2").isNotEqualTo(NEW_PASSWORD);
        });
    }

    @Test
    void theActorComesFromTheToken_neverFromTheBodyOrAHeader() {
        Map<String, Object> body = passwordBody(NEW_PASSWORD);
        body.put("actorUserId", SALES_ID);
        body.put("userId", INVENTORY_ID);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(tokenFor(ADMIN_ID, "ADMIN"));
        headers.set("Idempotency-Key", "reset-key-0004");
        headers.set("X-Actor-Id", SALES_ID);

        ResponseEntity<String> response = http.exchange("http://localhost:" + port + "/api/v1/auth/users/" + SALES_ID + "/password-reset",
            HttpMethod.POST, new HttpEntity<>(body, headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(store.calls).singleElement().satisfies(call -> {
            assertThat(call.attribution().actorUserId()).isEqualTo(ADMIN_ID);
            assertThat(call.targetUserId()).isEqualTo(SALES_ID);
        });
    }

    // ── 400 ──────────────────────────────────────────────────────────

    private List<String> fieldsOf(ResponseEntity<String> response) throws Exception {
        List<String> fields = new java.util.ArrayList<>();
        body(response).get("details").forEach(d -> fields.add(d.get("field").asText()));
        return fields;
    }

    @Test
    @Tag("AUTH-RESET-06")
    void aMissingIdempotencyKey_is400OnTheKey() throws Exception {
        ResponseEntity<String> response = resetAsAdmin(SALES_ID, null, passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(response).get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(fieldsOf(response)).containsExactly("Idempotency-Key");
        assertThat(store.calls).isEmpty();
    }

    @Test
    void aShortIdempotencyKey_is400() throws Exception {
        ResponseEntity<String> response = resetAsAdmin(SALES_ID, "short", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(fieldsOf(response)).containsExactly("Idempotency-Key");
    }

    @Test
    void aMalformedTargetId_is400OnTheId() throws Exception {
        ResponseEntity<String> response = resetAsAdmin("not-a-uuid", "reset-key-0005", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(fieldsOf(response)).containsExactly("id");
        assertThat(store.calls).isEmpty();
    }

    @Test
    void aTooShortPassword_is400_andTheMessageNeverRepeatsIt() throws Exception {
        ResponseEntity<String> response = resetAsAdmin(SALES_ID, "reset-key-0006", passwordBody("tiny-pw"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(fieldsOf(response)).containsExactly("newPassword");
        assertThat(response.getBody()).doesNotContain("tiny-pw");
    }

    @Test
    void aPasswordOfMoreThan72Bytes_is400() throws Exception {
        ResponseEntity<String> response = resetAsAdmin(SALES_ID, "reset-key-0007", passwordBody("x".repeat(73)));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(fieldsOf(response)).containsExactly("newPassword");
    }

    @Test
    void aConfirmationThatDiffers_is400OnTheConfirmation_andNeitherValueIsEchoed() throws Exception {
        Map<String, Object> mismatch = Map.of("newPassword", NEW_PASSWORD, "confirmPassword", NEW_PASSWORD + "-typo");

        ResponseEntity<String> response = resetAsAdmin(SALES_ID, "reset-key-0008", mismatch);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(fieldsOf(response)).containsExactly("confirmPassword");
        assertThat(response.getBody()).doesNotContain(NEW_PASSWORD);
        assertThat(store.calls).isEmpty();
    }

    @Test
    void aPasswordThatIsNotText_is400_itIsNeverCoercedIntoOne() throws Exception {
        Map<String, Object> numeric = Map.of("newPassword", 12345678, "confirmPassword", 12345678);

        ResponseEntity<String> response = resetAsAdmin(SALES_ID, "reset-key-0009", numeric);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(fieldsOf(response)).contains("newPassword");
        assertThat(store.calls).isEmpty();
    }

    @Test
    void aBodyThatIsNotAnObject_is400() throws Exception {
        ResponseEntity<String> response = resetAsAdmin(SALES_ID, "reset-key-0010", List.of("a", "b"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(fieldsOf(response)).contains("newPassword");
        assertThat(store.calls).isEmpty();
    }

    @Test
    void aMissingBody_is400InTheCommonEnvelope() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(tokenFor(ADMIN_ID, "ADMIN"));
        headers.set("Idempotency-Key", "reset-key-0011");

        ResponseEntity<String> response = http.exchange("http://localhost:" + port + "/api/v1/auth/users/" + SALES_ID + "/password-reset",
            HttpMethod.POST, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(response).get("error").asText()).isEqualTo("VALIDATION_ERROR");
    }

    // ── 404 / 422 ────────────────────────────────────────────────────

    @Test
    @Tag("AUTH-RESET-07")
    void anUnknownTarget_is404() throws Exception {
        ResponseEntity<String> response = resetAsAdmin(UUID.randomUUID().toString(), "reset-key-0012", passwordBody(NEW_PASSWORD));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(body(response).get("error").asText()).isEqualTo("NOT_FOUND");
        assertThat(store.calls).isEmpty();
    }

    @Test
    @Tag("AUTH-RESET-07")
    void anAdminTarget_andTheCallerThemselves_are422OnTheId() throws Exception {
        ResponseEntity<String> self = resetAsAdmin(ADMIN_ID, "reset-key-0013", passwordBody(NEW_PASSWORD));

        assertThat(self.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        assertThat(body(self).get("error").asText()).isEqualTo("BUSINESS_RULE_VIOLATION");
        assertThat(fieldsOf(self)).containsExactly("id");
        assertThat(store.calls).isEmpty();
    }

    @Test
    void errorBodiesNeverContainThePasswordOrTheToken() {
        String token = tokenFor(ADMIN_ID, "ADMIN");
        ResponseEntity<String> refused = reset(token, ADMIN_ID, "reset-key-0014", passwordBody(NEW_PASSWORD));

        assertThat(refused.getBody()).doesNotContain(NEW_PASSWORD).doesNotContain(token);
    }

    // ── the surface ──────────────────────────────────────────────────

    @Test
    void aGetOnTheResetRoute_isNotAReset() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(tokenFor(ADMIN_ID, "ADMIN"));

        ResponseEntity<String> response = http.exchange("http://localhost:" + port + "/api/v1/auth/users/" + SALES_ID + "/password-reset",
            HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(store.calls).isEmpty();
    }
}
