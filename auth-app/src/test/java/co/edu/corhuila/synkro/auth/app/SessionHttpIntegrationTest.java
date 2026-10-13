package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** logout and refresh-token reuse over real HTTP against the real PostgreSQL schema, with no fakes. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = DatabaseTestSupport.URL_VARIABLE, matches = ".+")
@ExtendWith(OutputCaptureExtension.class)
class SessionHttpIntegrationTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);
    private static final String PASSWORD = "pw-" + UUID.randomUUID();
    private static final Sha256HashFunction SHA = new Sha256HashFunction();

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "session-http-test");
        DatabaseTestSupport.registerDatasource(registry);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();
    private final JdbcTemplate jdbc = DatabaseTestSupport.jdbc();

    private record Session(String userId, String email, String accessToken, String refreshToken) {}

    // ── helpers ──────────────────────────────────────────────────────

    private ResponseEntity<String> post(String path, Object body, String bearer) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        return http.postForEntity("http://localhost:" + port + path, new HttpEntity<>(body, headers), String.class);
    }

    private ResponseEntity<String> loginResponse(String email) {
        return post("/api/v1/auth/login", Map.of("email", email, "password", PASSWORD), null);
    }

    private ResponseEntity<String> refresh(String refreshToken) {
        return post("/api/v1/auth/refresh", Map.of("refreshToken", refreshToken), null);
    }

    private ResponseEntity<String> logout(String accessToken, String refreshToken) {
        return post("/api/v1/auth/logout", Map.of("refreshToken", refreshToken), accessToken);
    }

    private JsonNode body(ResponseEntity<String> response) throws Exception {
        return json.readTree(response.getBody());
    }

    private Session newUserAndLogin(String role) throws Exception {
        String email = DatabaseTestSupport.uniqueEmail();
        String userId = DatabaseTestSupport.insertUser(jdbc, email, PASSWORD, role, true);
        JsonNode pair = body(loginResponse(email));
        return new Session(userId, email, pair.get("accessToken").asText(), pair.get("refreshToken").asText());
    }

    private static String serviceToken() {
        return Jwts.builder()
            .subject("synkro-workflow")
            .claim("roles", List.of("SERVICE"))
            .claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300)))
            .signWith(KEYS.getPrivate(), Jwts.SIG.RS256)
            .compact();
    }

    private boolean activeOf(String rawToken) {
        return jdbc.queryForObject("SELECT active FROM auth_schema.refresh_token WHERE token = ?", Boolean.class, SHA.hash(rawToken));
    }

    private int activeRowsOf(String userId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid AND active",
            Integer.class, userId);
    }

    private int rowsOf(String userId) {
        return jdbc.queryForObject("SELECT count(*) FROM auth_schema.refresh_token WHERE user_id = ?::uuid", Integer.class, userId);
    }

    private static List<String> detailFields(JsonNode error) {
        List<String> fields = new ArrayList<>();
        error.get("details").forEach(d -> fields.add(d.get("field").asText()));
        return fields;
    }

    // ── logout ───────────────────────────────────────────────────────

    @Test
    void logout_revokesTheRefreshToken_andALaterRefreshWithItIs401() throws Exception {
        Session ana = newUserAndLogin("ADMIN");

        ResponseEntity<String> response = logout(ana.accessToken(), ana.refreshToken());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(response).get("loggedOut").asBoolean()).isTrue();
        assertThat(activeOf(ana.refreshToken())).isFalse();
        assertThat(refresh(ana.refreshToken()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void logout_twiceWithTheSameToken_is200BothTimes() throws Exception {
        Session ana = newUserAndLogin("SALESPERSON");

        ResponseEntity<String> first = logout(ana.accessToken(), ana.refreshToken());
        ResponseEntity<String> second = logout(ana.accessToken(), ana.refreshToken());

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(second).get("loggedOut").asBoolean()).isTrue();
    }

    @Test
    void logout_ofAnUnknownToken_is200_andChangesNothing() throws Exception {
        Session ana = newUserAndLogin("INVENTORY");

        ResponseEntity<String> response = logout(ana.accessToken(), "never-issued-" + UUID.randomUUID());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(activeOf(ana.refreshToken())).isTrue();
    }

    @Test
    void logout_withATokenOfAnotherUser_is200_andThatTokenStillWorks() throws Exception {
        Session ana = newUserAndLogin("ADMIN");
        Session beto = newUserAndLogin("SALESPERSON");

        ResponseEntity<String> response = logout(beto.accessToken(), ana.refreshToken());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(body(response).get("loggedOut").asBoolean()).isTrue();
        assertThat(activeOf(ana.refreshToken())).isTrue();
        assertThat(refresh(ana.refreshToken()).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void logout_withAServiceToken_is403() throws Exception {
        Session ana = newUserAndLogin("ADMIN");

        ResponseEntity<String> response = logout(serviceToken(), ana.refreshToken());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(body(response).get("error").asText()).isEqualTo("FORBIDDEN");
        assertThat(activeOf(ana.refreshToken())).isTrue();
    }

    @Test
    void logout_withoutAToken_is401_andRevokesNothing() throws Exception {
        Session ana = newUserAndLogin("ADMIN");

        ResponseEntity<String> response = post("/api/v1/auth/logout", Map.of("refreshToken", ana.refreshToken()), null);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(activeOf(ana.refreshToken())).isTrue();
    }

    @Test
    void logout_withAMissingOrEmptyRefreshToken_is400_namingTheField() throws Exception {
        Session ana = newUserAndLogin("ADMIN");

        for (Object requestBody : List.of(Map.of(), Map.of("refreshToken", ""), Map.of("other", "x"))) {
            ResponseEntity<String> response = post("/api/v1/auth/logout", requestBody, ana.accessToken());

            assertThat(response.getStatusCode()).as("body %s", requestBody).isEqualTo(HttpStatus.BAD_REQUEST);
            JsonNode error = body(response);
            assertThat(error.get("error").asText()).isEqualTo("VALIDATION_ERROR");
            assertThat(detailFields(error)).containsExactly("refreshToken");
        }
    }

    // ── reuse detection ──────────────────────────────────────────────

    @Test
    void reusingARotatedToken_is401_andRevokesEveryTokenOfTheUser_untilTheyLogInAgain() throws Exception {
        Session ana = newUserAndLogin("ADMIN");
        String secondRefresh = body(refresh(ana.refreshToken())).get("refreshToken").asText();

        ResponseEntity<String> reuse = refresh(ana.refreshToken());

        assertThat(reuse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(activeRowsOf(ana.userId())).isZero();
        assertThat(refresh(secondRefresh).getStatusCode()).as("the token the legitimate rotation issued").isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(loginResponse(ana.email()).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(activeRowsOf(ana.userId())).isEqualTo(1);
    }

    @Test
    void reuse_deletesNoRow() throws Exception {
        Session ana = newUserAndLogin("ADMIN");
        refresh(ana.refreshToken());
        int rowsBefore = rowsOf(ana.userId());

        refresh(ana.refreshToken());

        assertThat(rowsOf(ana.userId())).isEqualTo(rowsBefore);
    }

    @Test
    void aRotatedTokenThatAlsoExpired_is401WithoutRevokingTheOtherSessions() throws Exception {
        Session ana = newUserAndLogin("ADMIN");
        String secondRefresh = body(refresh(ana.refreshToken())).get("refreshToken").asText();
        jdbc.update("UPDATE auth_schema.refresh_token SET expiration_date = now() - interval '1 second' WHERE token = ?",
            SHA.hash(ana.refreshToken()));

        ResponseEntity<String> response = refresh(ana.refreshToken());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(activeOf(secondRefresh)).isTrue();
        assertThat(refresh(secondRefresh).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void anUnknownToken_is401WithoutRevokingAnything() throws Exception {
        Session ana = newUserAndLogin("ADMIN");

        ResponseEntity<String> response = refresh("never-issued-" + UUID.randomUUID());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(activeRowsOf(ana.userId())).isEqualTo(1);
    }

    @Test
    void theReuseOfOneUser_leavesAnotherUsersSessionsAlone() throws Exception {
        Session ana = newUserAndLogin("ADMIN");
        Session beto = newUserAndLogin("SALESPERSON");
        refresh(ana.refreshToken());

        assertThat(refresh(ana.refreshToken()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        assertThat(activeOf(beto.refreshToken())).isTrue();
        assertThat(refresh(beto.refreshToken()).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // ── nothing secret in the output ─────────────────────────────────

    @Test
    void noTokenAndNoHash_appearsInAnyResponseBodyOrLogLine(CapturedOutput output) throws Exception {
        Session ana = newUserAndLogin("ADMIN");
        List<String> secrets = new ArrayList<>(List.of(ana.refreshToken(), SHA.hash(ana.refreshToken())));
        List<String> bodies = new ArrayList<>();

        String secondRefresh = body(refresh(ana.refreshToken())).get("refreshToken").asText();
        secrets.addAll(List.of(secondRefresh, SHA.hash(secondRefresh)));
        bodies.add(refresh(ana.refreshToken()).getBody());
        bodies.add(refresh(secondRefresh).getBody());
        Session beto = newUserAndLogin("INVENTORY");
        secrets.addAll(List.of(beto.refreshToken(), SHA.hash(beto.refreshToken())));
        bodies.add(logout(beto.accessToken(), beto.refreshToken()).getBody());
        bodies.add(logout(beto.accessToken(), beto.refreshToken()).getBody());
        bodies.add(logout(serviceToken(), beto.refreshToken()).getBody());
        bodies.add(post("/api/v1/auth/logout", Map.of("refreshToken", ""), beto.accessToken()).getBody());

        for (String secret : secrets) {
            assertThat(output.getAll()).as("log output").doesNotContain(secret);
            for (String responseBody : bodies) {
                assertThat(responseBody).as("response body").doesNotContain(secret);
            }
        }
    }
}
