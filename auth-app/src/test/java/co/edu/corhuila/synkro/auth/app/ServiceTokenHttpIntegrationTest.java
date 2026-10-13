package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/** Issuing and reading service tokens over real HTTP against the real PostgreSQL schema, with no fakes. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
@ExtendWith(OutputCaptureExtension.class)
class ServiceTokenHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();
    private static final List<String> METADATA_FIELDS =
        List.of("tokenId", "service", "permissions", "issuedBy", "issuedAt", "expiresAt");
    private static final List<String> WORKFLOW_PERMISSIONS =
        List.of("customers:read", "stock:reserve", "stock:release", "sales:register");
    private static final List<String> WORKER_PERMISSIONS =
        List.of("products:read", "stock-alerts:read", "stock-alerts:write");

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "service-token-http-test");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();

    private static String adminId;
    private static String adminToken;

    // ── helpers ──────────────────────────────────────────────────────


    private void ensureAdmin() throws Exception {
        if (adminToken != null) {
            return;
        }
        String email = DatabaseTestSupport.uniqueEmail();
        // register is an ADMIN-only operation, so the first administrator is seeded in the database.
        adminId = DatabaseTestSupport.insertUser(jdbc, email, PASSWORD, "ADMIN", true);
        ResponseEntity<String> login = send(HttpMethod.POST, "/api/v1/auth/login",
            Map.of("email", email, "password", PASSWORD), null);
        adminToken = body(login).get("accessToken").asText();
    }

    private static String newKey() {
        return "it-key-" + UUID.randomUUID();
    }

    private ResponseEntity<String> send(HttpMethod method, String path, Object body, String token, String... headerPairs) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        for (int i = 0; i < headerPairs.length; i += 2) {
            headers.set(headerPairs[i], headerPairs[i + 1]);
        }
        return http.exchange("http://localhost:" + port + path, method, new HttpEntity<>(body, headers), String.class);
    }

    private ResponseEntity<String> issue(String token, String key, Object body) {
        return key == null
            ? send(HttpMethod.POST, "/api/v1/auth/service-tokens", body, token)
            : send(HttpMethod.POST, "/api/v1/auth/service-tokens", body, token, "Idempotency-Key", key);
    }

    private ResponseEntity<String> issueAsAdmin(String key, String service) throws Exception {
        ensureAdmin();
        return issue(adminToken, key, Map.of("service", service));
    }

    private ResponseEntity<String> lookup(String id, String token) {
        return send(HttpMethod.GET, "/api/v1/auth/service-tokens/" + id, null, token);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private static String tokenFor(String role) {
        return Jwts.builder()
            .subject(UUID.randomUUID().toString())
            .claim("roles", List.of(role))
            .claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300)))
            .signWith(KEYS.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private static Jws<Claims> parse(String token) {
        return Jwts.parser().verifyWith(KEYS.getPublic()).build().parseSignedClaims(token);
    }

    private int tokenRows() {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.service_token", Integer.class);
    }

    private int keyRows() {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.idempotency_key", Integer.class);
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        Iterator<String> iterator = node.fieldNames();
        iterator.forEachRemaining(names::add);
        return names;
    }

    private static List<String> detailFields(JsonNode error) {
        List<String> fields = new ArrayList<>();
        error.get("details").forEach(d -> fields.add(d.get("field").asText()));
        return fields;
    }

    private static List<String> texts(JsonNode array) {
        List<String> values = new ArrayList<>();
        array.forEach(item -> values.add(item.asText()));
        return values;
    }

    // ── 13: issuing ──────────────────────────────────────────────────

    @ParameterizedTest
    @MethodSource("services")
    void anAdminIssuesATokenForEachService_201WithLocation_andTheClaimsMatchTheMetadata(String service, List<String> permissions)
            throws Exception {
        ResponseEntity<String> response = issueAsAdmin(newKey(), service);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        JsonNode created = body(response);
        List<String> expectedFields = new ArrayList<>(METADATA_FIELDS);
        expectedFields.add("token");
        assertThat(fieldNames(created)).containsExactlyInAnyOrderElementsOf(expectedFields);
        assertThat(created.get("service").asText()).isEqualTo(service);
        assertThat(texts(created.get("permissions"))).containsExactlyInAnyOrderElementsOf(permissions);
        assertThat(created.get("issuedBy").asText()).isEqualTo(adminId);
        assertThat(response.getHeaders().getLocation())
            .hasToString("/api/v1/auth/service-tokens/" + created.get("tokenId").asText());

        Instant issuedAt = Instant.parse(created.get("issuedAt").asText());
        Instant expiresAt = Instant.parse(created.get("expiresAt").asText());
        assertThat(Duration.between(issuedAt, expiresAt)).isEqualTo(Duration.ofDays(30));
        assertThat(issuedAt).isBetween(Instant.now().minusSeconds(60), Instant.now().plusSeconds(5));

        Jws<Claims> jws = parse(created.get("token").asText());
        assertThat(jws.getHeader().getAlgorithm()).isEqualTo("RS256");
        Claims claims = jws.getPayload();
        assertThat(claims.getSubject()).isEqualTo(service);
        assertThat(claims.get("roles", List.class)).containsExactly("SERVICE");
        assertThat(claims.get("permissions", List.class)).containsExactlyInAnyOrderElementsOf(permissions);
        assertThat(claims.getId()).isEqualTo(created.get("tokenId").asText());
        assertThat(claims.getIssuedAt().toInstant()).isEqualTo(issuedAt);
        assertThat(claims.getExpiration().toInstant()).isEqualTo(expiresAt);
    }

    static Stream<Arguments> services() {
        return Stream.of(Arguments.of("synkro-workflow", WORKFLOW_PERMISSIONS), Arguments.of("synkro-worker", WORKER_PERMISSIONS));
    }

    @Test
    void thePermissionsAndTheIssuerSentInTheRequestAreIgnored_theFixedOnesAreUsed() throws Exception {
        ensureAdmin();
        Map<String, Object> request = new HashMap<>();
        request.put("service", "synkro-worker");
        request.put("permissions", List.of("users:manage", "sales:register"));
        request.put("issuedBy", UUID.randomUUID().toString());
        request.put("roles", List.of("ADMIN"));

        ResponseEntity<String> response = issue(adminToken, newKey(), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        JsonNode created = body(response);
        assertThat(texts(created.get("permissions"))).containsExactlyInAnyOrderElementsOf(WORKER_PERMISSIONS);
        assertThat(created.get("issuedBy").asText()).isEqualTo(adminId);
        Claims claims = parse(created.get("token").asText()).getPayload();
        assertThat(claims.get("permissions", List.class)).containsExactlyInAnyOrderElementsOf(WORKER_PERMISSIONS);
        assertThat(claims.get("roles", List.class)).containsExactly("SERVICE");
    }

    // ── 14, 15: idempotency ──────────────────────────────────────────

    @Test
    void theSameKeyAndBodyAgain_is200WithTheMetadataAndNoToken_andNothingIsCreated() throws Exception {
        String key = newKey();
        ResponseEntity<String> first = issueAsAdmin(key, "synkro-workflow");
        int tokens = tokenRows();
        int keys = keyRows();

        ResponseEntity<String> again = issueAsAdmin(key, "synkro-workflow");

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(again.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode replay = body(again);
        assertThat(fieldNames(replay)).containsExactlyInAnyOrderElementsOf(METADATA_FIELDS);
        for (String field : METADATA_FIELDS) {
            assertThat(replay.get(field)).isEqualTo(body(first).get(field));
        }
        assertThat(again.getBody()).doesNotContain(body(first).get("token").asText());
        assertThat(tokenRows()).isEqualTo(tokens);
        assertThat(keyRows()).isEqualTo(keys);
    }

    @Test
    void theSameKeyWithAnotherService_is422NamingTheIdempotencyKey_andShowsNothingOfTheFirstToken() throws Exception {
        String key = newKey();
        JsonNode first = body(issueAsAdmin(key, "synkro-worker"));
        int tokens = tokenRows();

        ResponseEntity<String> other = issueAsAdmin(key, "synkro-workflow");

        assertThat(other.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        JsonNode error = body(other);
        assertThat(error.get("error").asText()).isEqualTo("BUSINESS_RULE_VIOLATION");
        assertThat(detailFields(error)).containsExactly("Idempotency-Key");
        assertThat(other.getBody()).doesNotContain(first.get("tokenId").asText()).doesNotContain(first.get("token").asText());
        assertThat(tokenRows()).isEqualTo(tokens);
    }

    @Test
    void twoSimultaneousRequestsWithTheSameKey_createOneRow_oneIs201WithTheTokenAndTheOtherIs200WithoutIt() throws Exception {
        ensureAdmin();
        String key = newKey();
        int tokens = tokenRows();

        List<ResponseEntity<String>> responses = together(
            () -> issue(adminToken, key, Map.of("service", "synkro-workflow")),
            () -> issue(adminToken, key, Map.of("service", "synkro-workflow")));

        assertThat(responses).extracting(r -> r.getStatusCode().value()).containsExactlyInAnyOrder(201, 200);
        ResponseEntity<String> created = responses.stream().filter(r -> r.getStatusCode() == HttpStatus.CREATED).findFirst().orElseThrow();
        ResponseEntity<String> replayed = responses.stream().filter(r -> r.getStatusCode() == HttpStatus.OK).findFirst().orElseThrow();
        assertThat(body(replayed).has("token")).isFalse();
        assertThat(body(replayed).get("tokenId")).isEqualTo(body(created).get("tokenId"));
        assertThat(tokenRows()).isEqualTo(tokens + 1);
    }

    @SafeVarargs
    private <T> List<T> together(Callable<T>... tasks) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(tasks.length);
        CountDownLatch ready = new CountDownLatch(tasks.length);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<T>> futures = new ArrayList<>();
        for (Callable<T> task : tasks) {
            futures.add(pool.submit(() -> {
                ready.countDown();
                go.await();
                return task.call();
            }));
        }
        ready.await();
        go.countDown();
        List<T> results = new ArrayList<>();
        for (Future<T> future : futures) {
            results.add(future.get());
        }
        pool.shutdown();
        return results;
    }

    // ── 16: validation ───────────────────────────────────────────────

    @ParameterizedTest
    @MethodSource("badKeys")
    void aMissingOrOutOfRangeKey_is400NamingTheHeader_andCreatesNothing(String key) throws Exception {
        ensureAdmin();
        int tokens = tokenRows();
        int keys = keyRows();

        ResponseEntity<String> response = issue(adminToken, key, Map.of("service", "synkro-worker"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode error = body(response);
        assertThat(error.get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(detailFields(error)).containsExactly("Idempotency-Key");
        assertThat(tokenRows()).isEqualTo(tokens);
        assertThat(keyRows()).isEqualTo(keys);
    }

    static Stream<Arguments> badKeys() {
        return Stream.of(Arguments.of((String) null), Arguments.of("1234567"), Arguments.of("k".repeat(129)));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidServices")
    void aMissingOrUnknownService_is400NamingTheField_andCreatesNothing(String label, Map<String, Object> request) throws Exception {
        ensureAdmin();
        int tokens = tokenRows();

        ResponseEntity<String> response = issue(adminToken, newKey(), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode error = body(response);
        assertThat(error.get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(detailFields(error)).containsExactly("service");
        assertThat(tokenRows()).isEqualTo(tokens);
    }

    static Stream<Arguments> invalidServices() {
        Map<String, Object> nullService = new HashMap<>();
        nullService.put("service", null);
        return Stream.of(
            Arguments.of("no field", Map.<String, Object>of()),
            Arguments.of("null", nullService),
            Arguments.of("empty", Map.<String, Object>of("service", "")),
            Arguments.of("unknown service", Map.<String, Object>of("service", "synkro-sales")),
            Arguments.of("wrong case", Map.<String, Object>of("service", "SYNKRO-WORKER")),
            Arguments.of("a role is not a service", Map.<String, Object>of("service", "ADMIN")));
    }

    @Test
    void aBodyThatIsNotJson_is400_andCreatesNothing() throws Exception {
        ensureAdmin();
        int tokens = tokenRows();

        ResponseEntity<String> response = send(HttpMethod.POST, "/api/v1/auth/service-tokens", "{not json", adminToken,
            "Idempotency-Key", newKey());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(body(response).get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(tokenRows()).isEqualTo(tokens);
    }

    // ── 17: lookup ───────────────────────────────────────────────────

    @Test
    void anAdminReadsTheMetadata_andTheBodyNeverCarriesTheToken() throws Exception {
        JsonNode created = body(issueAsAdmin(newKey(), "synkro-worker"));

        ResponseEntity<String> response = lookup(created.get("tokenId").asText(), adminToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode metadata = body(response);
        assertThat(fieldNames(metadata)).containsExactlyInAnyOrderElementsOf(METADATA_FIELDS);
        for (String field : METADATA_FIELDS) {
            assertThat(metadata.get(field)).isEqualTo(created.get(field));
        }
        assertThat(response.getBody()).doesNotContain(created.get("token").asText());
    }

    @Test
    void theLocationOfA201_isReadableByTheAdmin() throws Exception {
        ResponseEntity<String> created = issueAsAdmin(newKey(), "synkro-workflow");

        ResponseEntity<String> response = send(HttpMethod.GET, created.getHeaders().getLocation().toString(), null, adminToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(response).get("service").asText()).isEqualTo("synkro-workflow");
    }

    @Test
    void anUnknownOrMalformedId_is404NotFound() throws Exception {
        ensureAdmin();

        for (String id : new String[] {UUID.randomUUID().toString(), "not-a-uuid", "12345"}) {
            ResponseEntity<String> response = lookup(id, adminToken);

            assertThat(response.getStatusCode()).as(id).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(body(response).get("error").asText()).isEqualTo("NOT_FOUND");
        }
    }

    // ── 18: who may call ─────────────────────────────────────────────

    @ParameterizedTest
    @ValueSource(strings = {"SALESPERSON", "INVENTORY"})
    void aSalespersonOrInventoryUser_is403OnBothEndpoints_andCreatesNothing(String role) throws Exception {
        String id = body(issueAsAdmin(newKey(), "synkro-worker")).get("tokenId").asText();
        int tokens = tokenRows();
        int keys = keyRows();

        ResponseEntity<String> issued = issue(tokenFor(role), newKey(), Map.of("service", "synkro-worker"));
        ResponseEntity<String> read = lookup(id, tokenFor(role));

        for (ResponseEntity<String> response : List.of(issued, read)) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        }
        assertThat(tokenRows()).isEqualTo(tokens);
        assertThat(keyRows()).isEqualTo(keys);
    }

    @Test
    void aServiceTokenCannotIssueOrReadTokens_403OnBothEndpoints() throws Exception {
        JsonNode created = body(issueAsAdmin(newKey(), "synkro-workflow"));
        String serviceToken = created.get("token").asText();
        int tokens = tokenRows();

        ResponseEntity<String> issued = issue(serviceToken, newKey(), Map.of("service", "synkro-worker"));
        ResponseEntity<String> read = lookup(created.get("tokenId").asText(), serviceToken);

        assertThat(issued.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(read.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(tokenRows()).isEqualTo(tokens);
    }

    @Test
    void noToken_is401OnBothEndpoints() throws Exception {
        String id = body(issueAsAdmin(newKey(), "synkro-worker")).get("tokenId").asText();
        int tokens = tokenRows();

        ResponseEntity<String> issued = issue(null, newKey(), Map.of("service", "synkro-worker"));
        ResponseEntity<String> read = lookup(id, null);

        for (ResponseEntity<String> response : List.of(issued, read)) {
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(body(response).get("error").asText()).isEqualTo("UNAUTHORIZED");
        }
        assertThat(tokenRows()).isEqualTo(tokens);
    }

    // ── 19: the token authenticates ──────────────────────────────────

    @Test
    void theIssuedToken_asABearer_authenticatesAsAServiceCallerWithExactlyItsPermissions() throws Exception {
        String serviceToken = body(issueAsAdmin(newKey(), "synkro-workflow")).get("token").asText();

        ResponseEntity<String> whoami = send(HttpMethod.GET, "/test-probe/whoami", null, serviceToken);
        ResponseEntity<String> adminOnly = send(HttpMethod.GET, "/test-probe/admin-only", null, serviceToken);

        assertThat(whoami.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode caller = body(whoami);
        assertThat(caller.get("subject").asText()).isEqualTo("synkro-workflow");
        assertThat(texts(caller.get("roles"))).containsExactly("SERVICE");
        assertThat(texts(caller.get("permissions"))).containsExactlyInAnyOrderElementsOf(WORKFLOW_PERMISSIONS);
        assertThat(adminOnly.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── 20: the token is never kept or repeated ──────────────────────

    @Test
    void neitherTheTokenNorAPartOfItAppearsInALaterResponse_theDatabaseOrTheLog(CapturedOutput output) throws Exception {
        String key = newKey();
        JsonNode created = body(issueAsAdmin(key, "synkro-workflow"));
        String token = created.get("token").asText();
        String[] parts = token.split("\\.");
        // The start of a payload is the same for every token of a service, so only the tail (which holds the jti) is a fragment unique to this token.
        List<String> secrets = List.of(token, parts[1], parts[2], parts[1].substring(parts[1].length() - 60), parts[2].substring(0, 40));
        List<String> laterResponses = new ArrayList<>();
        laterResponses.add(issueAsAdmin(key, "synkro-workflow").getBody());
        laterResponses.add(issueAsAdmin(key, "synkro-worker").getBody());
        laterResponses.add(lookup(created.get("tokenId").asText(), adminToken).getBody());
        laterResponses.add(lookup(UUID.randomUUID().toString(), adminToken).getBody());
        laterResponses.add(issue(token, newKey(), Map.of("service", "synkro-worker")).getBody());
        laterResponses.add(lookup(created.get("tokenId").asText(), token).getBody());
        String tables = jdbc.queryForObject(
            "SELECT coalesce((SELECT string_agg(t::text, ' ') FROM auth_schema.service_token t), '') "
                + "|| ' ' || coalesce((SELECT string_agg(k::text, ' ') FROM auth_schema.idempotency_key k), '')", String.class);

        for (String secret : secrets) {
            assertThat(laterResponses).allSatisfy(response -> assertThat(response).doesNotContain(secret));
            assertThat(tables).doesNotContain(secret);
            assertThat(output.getAll()).doesNotContain(secret);
        }
    }
}
