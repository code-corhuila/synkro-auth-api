package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Tag;
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

import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A database that cannot answer is not an administrator that does not exist: with a valid ADMIN token and nobody
 * listening on the datasource, register is an infrastructure failure (500), never the 403 reserved for an unknown actor.
 * Needs no database, so it always runs.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RegisterActorLookupUnavailableHttpTest {

    private static final KeyPair KEYS = TestKeys.generate(2048);

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, KEYS, "register-actor-lookup-unavailable-test");
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://127.0.0.1:1/unreachable_db");
        registry.add("spring.datasource.username", () -> "auth_app");
        registry.add("spring.datasource.password", () -> "pw-" + UUID.randomUUID());
        registry.add("spring.datasource.hikari.connection-timeout", () -> "1000");
    }

    @LocalServerPort
    int port;

    @Test
    @Tag("AUTH-REG-02")
    void whenTheActorCannotBeLookedUp_registerIs500InternalError_notForbidden() throws Exception {
        String token = Jwts.builder().subject(UUID.randomUUID().toString()).claim("roles", List.of("ADMIN")).claim("permissions", List.of())
            .expiration(Date.from(Instant.now().plusSeconds(300))).signWith(KEYS.getPrivate(), Jwts.SIG.RS256).compact();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);
        headers.set("Idempotency-Key", "it-key-" + UUID.randomUUID());
        headers.set("X-Correlation-Id", "corr-actor-db-down");

        ResponseEntity<String> response = new TestRestTemplate().exchange("http://localhost:" + port + "/api/v1/auth/register",
            HttpMethod.POST, new HttpEntity<>(Map.of("name", "Ana", "email", "ana@synkro.test", "password", "a-long-password", "role", "INVENTORY"), headers),
            String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        JsonNode body = new ObjectMapper().readTree(response.getBody());
        assertThat(body.get("error").asText()).isEqualTo("INTERNAL_ERROR");
        assertThat(body.get("traceId").asText()).isEqualTo("corr-actor-db-down");
        assertThat(response.getBody()).doesNotContainIgnoringCase("jdbc:").doesNotContain("127.0.0.1").doesNotContain("FORBIDDEN");
    }
}
