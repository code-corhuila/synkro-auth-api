package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** logout and reuse through the real filter chain with in-memory persistence, so they run without a database. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(InMemoryAdaptersTestConfig.class)
class LogoutHttpTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("logout-http-test");
        Path key = TestKeys.writePrivateKeyPem(KEYS, dir);
        registry.add("JWT_PRIVATE_KEY_FILE", key::toString);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();

    private ResponseEntity<String> post(String path, Object body, String bearer) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (bearer != null) {
            headers.setBearerAuth(bearer);
        }
        return http.postForEntity("http://localhost:" + port + path, new HttpEntity<>(body, headers), String.class);
    }

    private JsonNode loginAsAdmin() throws Exception {
        ResponseEntity<String> response = post("/api/v1/auth/login",
            Map.of("email", "admin@synkro.test", "password", "admin-dev-password"), null);
        return json.readTree(response.getBody());
    }

    private ResponseEntity<String> refresh(String refreshToken) {
        return post("/api/v1/auth/refresh", Map.of("refreshToken", refreshToken), null);
    }

    @Test
    void logout_revokesTheToken_andTheNextRefreshIs401() throws Exception {
        JsonNode pair = loginAsAdmin();
        String access = pair.get("accessToken").asText();
        String refreshToken = pair.get("refreshToken").asText();

        ResponseEntity<String> response = post("/api/v1/auth/logout", Map.of("refreshToken", refreshToken), access);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(json.readTree(response.getBody()).get("loggedOut").asBoolean()).isTrue();
        assertThat(refresh(refreshToken).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/api/v1/auth/logout", Map.of("refreshToken", refreshToken), access).getStatusCode())
            .isEqualTo(HttpStatus.OK);
    }

    @Test
    void logout_withoutAccessToken_is401_andAServiceToken_is403() throws Exception {
        String refreshToken = loginAsAdmin().get("refreshToken").asText();
        String service = Jwts.builder().subject("synkro-workflow").claim("roles", List.of("SERVICE")).claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300))).signWith(KEYS.getPrivate(), Jwts.SIG.RS256).compact();

        assertThat(post("/api/v1/auth/logout", Map.of("refreshToken", refreshToken), null).getStatusCode())
            .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(post("/api/v1/auth/logout", Map.of("refreshToken", refreshToken), service).getStatusCode())
            .isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(refresh(refreshToken).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void logout_withAnEmptyRefreshToken_is400_namingTheField() throws Exception {
        String access = loginAsAdmin().get("accessToken").asText();

        ResponseEntity<String> response = post("/api/v1/auth/logout", Map.of("refreshToken", ""), access);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(json.readTree(response.getBody()).get("details").get(0).get("field").asText()).isEqualTo("refreshToken");
    }

    @Test
    void reusingARotatedToken_is401_andTheTokenOfTheRotationStopsWorking() throws Exception {
        String first = loginAsAdmin().get("refreshToken").asText();
        String second = json.readTree(refresh(first).getBody()).get("refreshToken").asText();

        assertThat(refresh(first).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refresh(second).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(loginAsAdmin().get("refreshToken").asText()).isNotBlank();
    }
}
