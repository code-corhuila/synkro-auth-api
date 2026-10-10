package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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

/** register and the user lookup over real HTTP against the real PostgreSQL schema, with no fakes. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
class RegisterAndLookupHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "register-lookup-http-test");
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

    private ResponseEntity<String> register(Map<String, Object> body, String key) {
        return key == null
            ? send(HttpMethod.POST, "/api/v1/auth/register", body, null)
            : send(HttpMethod.POST, "/api/v1/auth/register", body, null, "Idempotency-Key", key);
    }

    private ResponseEntity<String> lookup(String id, String token) {
        return send(HttpMethod.GET, "/api/v1/auth/users/" + id, null, token);
    }

    private ResponseEntity<String> login(String email, String password) {
        return send(HttpMethod.POST, "/api/v1/auth/login", Map.of("email", email, "password", password), null);
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

    private int usersWithEmail(String email) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.system_user WHERE lower(email) = lower(?)", Integer.class, email);
    }

    private int totalUsers() {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.system_user", Integer.class);
    }

    private int totalKeys() {
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

    // ── 11: register ─────────────────────────────────────────────────

    @Test
    void register_creates201WithLocation_andABodyWithoutThePasswordOrItsHash() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();

        ResponseEntity<String> response = register(request(email, "SALESPERSON"), newKey());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        JsonNode user = body(response);
        assertThat(fieldNames(user)).containsExactlyInAnyOrder("userId", "name", "email", "role", "registrationDate", "active");
        assertThat(user.get("email").asText()).isEqualTo(email);
        assertThat(user.get("role").asText()).isEqualTo("SALESPERSON");
        assertThat(user.get("active").asBoolean()).isTrue();
        assertThat(Instant.parse(user.get("registrationDate").asText())).isBefore(Instant.now().plusSeconds(5));
        assertThat(response.getHeaders().getLocation()).hasToString("/api/v1/auth/users/" + user.get("userId").asText());

        String storedHash = jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE email = ?", String.class, email);
        assertThat(storedHash).startsWith("$2").isNotEqualTo(PASSWORD);
        assertThat(response.getBody()).doesNotContain(storedHash).doesNotContain(PASSWORD).doesNotContainIgnoringCase("hash");
    }

    @Test
    void aRegisteredUser_canLogIn() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        register(request(email, "INVENTORY"), newKey());

        ResponseEntity<String> response = login(email, PASSWORD);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(response).get("accessToken").asText()).isNotBlank();
    }

    @Test
    void theEmailIsMatchedWithoutCaseOrSurroundingSpaces_onRegisterAndOnLogin() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        register(request("  " + email.toUpperCase() + " ", "ADMIN"), newKey());

        assertThat(jdbc.queryForObject("SELECT email FROM auth_schema.system_user WHERE lower(email) = ?", String.class, email))
            .isEqualTo(email);
        assertThat(login(email, PASSWORD).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(login(email.toUpperCase(), PASSWORD).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(register(request(email, "ADMIN"), newKey()).getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    }

    // ── 12: idempotency ──────────────────────────────────────────────

    @Test
    void theSameKeyAgain_is200WithTheSameUser_andNothingIsCreated() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String key = newKey();
        ResponseEntity<String> first = register(request(email, "ADMIN"), key);
        int users = totalUsers();
        int keys = totalKeys();

        ResponseEntity<String> again = register(request(email, "ADMIN"), key);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(again.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(again).get("userId")).isEqualTo(body(first).get("userId"));
        assertThat(body(again).get("registrationDate")).isEqualTo(body(first).get("registrationDate"));
        assertThat(totalUsers()).isEqualTo(users);
        assertThat(totalKeys()).isEqualTo(keys);
    }

    @Test
    void theSameKeyWithADifferentBody_is422_andShowsNothingOfTheFirstUser() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String key = newKey();
        register(request(email, "ADMIN"), key);

        ResponseEntity<String> other = register(request(DatabaseTestSupport.uniqueEmail(), "ADMIN"), key);

        assertThat(other.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        JsonNode error = body(other);
        assertThat(error.get("error").asText()).isEqualTo("BUSINESS_RULE_VIOLATION");
        assertThat(detailFields(error)).containsExactly("Idempotency-Key");
        assertThat(other.getBody()).doesNotContain(email);
    }

    // ── 13: the Idempotency-Key header ───────────────────────────────

    @ParameterizedTest
    @MethodSource("badKeys")
    void aMissingOrOutOfRangeKey_is400ValidationError_andCreatesNothing(String key) throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();

        ResponseEntity<String> response = register(request(email, "ADMIN"), key);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode error = body(response);
        assertThat(error.get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(detailFields(error)).containsExactly("Idempotency-Key");
        assertThat(usersWithEmail(email)).isZero();
    }

    static Stream<Arguments> badKeys() {
        return Stream.of(Arguments.of((String) null), Arguments.of("1234567"), Arguments.of("k".repeat(129)));
    }

    // ── 14: every invalid field ──────────────────────────────────────

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidBodies")
    void anInvalidField_is400ValidationErrorNamingIt_andCreatesNothing(String label, String field, Map<String, Object> body) throws Exception {
        int users = totalUsers();

        ResponseEntity<String> response = register(body, newKey());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        JsonNode error = body(response);
        assertThat(error.get("error").asText()).isEqualTo("VALIDATION_ERROR");
        assertThat(detailFields(error)).contains(field);
        assertThat(totalUsers()).isEqualTo(users);
    }

    static Stream<Arguments> invalidBodies() {
        return Stream.of(
            Arguments.of("empty name", "name", with("name", "")),
            Arguments.of("151-character name", "name", with("name", "n".repeat(151))),
            Arguments.of("malformed email", "email", with("email", "not-an-email")),
            Arguments.of("2-character email", "email", with("email", "a@")),
            Arguments.of("256-character email", "email", with("email", "a".repeat(244) + "@synkro.test")),
            Arguments.of("7-character password", "password", with("password", "1234567")),
            Arguments.of("missing name", "name", without("name")),
            Arguments.of("missing email", "email", without("email")),
            Arguments.of("missing password", "password", without("password")),
            Arguments.of("missing role", "role", without("role")),
            Arguments.of("role SERVICE", "role", with("role", "SERVICE")),
            Arguments.of("role OWNER", "role", with("role", "OWNER")));
    }

    private static Map<String, Object> with(String field, Object value) {
        Map<String, Object> body = request("it-" + UUID.randomUUID() + "@synkro.test", "ADMIN");
        body.put(field, value);
        return body;
    }

    private static Map<String, Object> without(String field) {
        Map<String, Object> body = request("it-" + UUID.randomUUID() + "@synkro.test", "ADMIN");
        body.remove(field);
        return body;
    }

    // ── 15: business rule ────────────────────────────────────────────

    @Test
    void anExistingEmailWithANewKey_is422BusinessRuleViolation_namingEmail() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        register(request(email, "ADMIN"), newKey());

        ResponseEntity<String> response = register(request(email, "SALESPERSON"), newKey());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
        JsonNode error = body(response);
        assertThat(error.get("error").asText()).isEqualTo("BUSINESS_RULE_VIOLATION");
        assertThat(detailFields(error)).containsExactly("email");
        assertThat(usersWithEmail(email)).isEqualTo(1);
    }

    @Test
    void twoSimultaneousRequestsWithTheSameKey_createOneUser_andBothSucceed() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String key = newKey();

        List<ResponseEntity<String>> responses = together(
            () -> register(request(email, "ADMIN"), key),
            () -> register(request(email, "ADMIN"), key));

        assertThat(responses).extracting(r -> r.getStatusCode().value()).containsExactlyInAnyOrder(201, 200);
        assertThat(body(responses.get(0)).get("userId")).isEqualTo(body(responses.get(1)).get("userId"));
        assertThat(usersWithEmail(email)).isEqualTo(1);
    }

    @Test
    void twoSimultaneousRequestsWithTheSameEmailAndDifferentKeys_createOneUser_andNeverAnswer500() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();

        List<ResponseEntity<String>> responses = together(
            () -> register(request(email, "ADMIN"), newKey()),
            () -> register(request(email, "ADMIN"), newKey()));

        assertThat(responses).extracting(r -> r.getStatusCode().value()).containsExactlyInAnyOrder(201, 422);
        assertThat(usersWithEmail(email)).isEqualTo(1);
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

    // ── 16: lookup ───────────────────────────────────────────────────

    private String registeredId(String email, String role) throws Exception {
        return body(register(request(email, role), newKey())).get("userId").asText();
    }

    @Test
    void anAdminReadsAUser_andTheBodyNeverCarriesTheHash() throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String id = registeredId(email, "INVENTORY");
        String storedHash = jdbc.queryForObject("SELECT password_hash FROM auth_schema.system_user WHERE email = ?", String.class, email);

        ResponseEntity<String> response = lookup(id, tokenFor("ADMIN"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode user = body(response);
        assertThat(fieldNames(user)).containsExactlyInAnyOrder("userId", "name", "email", "role", "registrationDate", "active");
        assertThat(user.get("userId").asText()).isEqualTo(id);
        assertThat(user.get("email").asText()).isEqualTo(email);
        assertThat(response.getBody()).doesNotContain("passwordHash").doesNotContain("password").doesNotContain(storedHash);
    }

    @Test
    void anAdminWhoLoggedInForReal_canReadTheUserTheLocationPointsTo() throws Exception {
        String adminEmail = DatabaseTestSupport.uniqueEmail();
        register(request(adminEmail, "ADMIN"), newKey());
        String token = body(login(adminEmail, PASSWORD)).get("accessToken").asText();
        ResponseEntity<String> created = register(request(DatabaseTestSupport.uniqueEmail(), "SALESPERSON"), newKey());

        ResponseEntity<String> response = send(HttpMethod.GET, created.getHeaders().getLocation().toString(), null, token);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(response).get("role").asText()).isEqualTo("SALESPERSON");
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"SALESPERSON", "INVENTORY", "SERVICE"})
    void anyOtherRole_is403Forbidden(String role) throws Exception {
        String id = registeredId(DatabaseTestSupport.uniqueEmail(), "ADMIN");

        ResponseEntity<String> response = lookup(id, tokenFor(role));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
    }

    @Test
    void noToken_is401() throws Exception {
        String id = registeredId(DatabaseTestSupport.uniqueEmail(), "ADMIN");

        ResponseEntity<String> response = lookup(id, null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(body(response).get("error").asText()).isEqualTo("UNAUTHORIZED");
    }

    @Test
    void anUnknownId_is404NotFound() throws Exception {
        ResponseEntity<String> response = lookup(UUID.randomUUID().toString(), tokenFor("ADMIN"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(body(response).get("error").asText()).isEqualTo("NOT_FOUND");
    }

    @Test
    void aMalformedId_is404NotFound_andForANonAdminStill403() throws Exception {
        assertThat(lookup("not-a-uuid", tokenFor("ADMIN")).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(lookup("not-a-uuid", tokenFor("SALESPERSON")).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // ── 17: which route is public ────────────────────────────────────

    @Test
    void registerIsReachableWithNoToken_theLookupIsNot() throws Exception {
        ResponseEntity<String> registered = register(request(DatabaseTestSupport.uniqueEmail(), "ADMIN"), newKey());
        ResponseEntity<String> looked = lookup(body(registered).get("userId").asText(), null);

        assertThat(registered.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(looked.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
