package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The service starts with a datasource nobody listens on, then every request that needs
 * the database must answer 500 INTERNAL_ERROR in the common envelope, leaking nothing.
 * Needs no database, so it always runs.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class DatabaseUnavailableHttpTest {

    private static final String PASSWORD = "pw-" + UUID.randomUUID();

    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry registry) throws Exception {
        DatabaseTestSupport.registerSigningKey(registry, TestKeys.generate(2048), "database-unavailable-test");
        registry.add("spring.datasource.url", () -> "jdbc:postgresql://127.0.0.1:1/unreachable_db");
        registry.add("spring.datasource.username", () -> "auth_app");
        registry.add("spring.datasource.password", () -> PASSWORD);
        registry.add("spring.datasource.hikari.connection-timeout", () -> "1000");
    }

    @LocalServerPort
    int port;

    @Test
    void whenTheDatabaseCannotBeReached_loginIs500InTheCommonEnvelope_withoutLeaks(CapturedOutput output) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Correlation-Id", "corr-db-down");

        ResponseEntity<String> response = new TestRestTemplate().postForEntity(
            "http://localhost:" + port + "/api/v1/auth/login",
            new HttpEntity<>(Map.of("email", "someone@synkro.test", "password", "x"), headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        JsonNode body = new ObjectMapper().readTree(response.getBody());
        assertThat(body.get("error").asText()).isEqualTo("INTERNAL_ERROR");
        assertThat(body.get("message").asText()).isNotBlank();
        assertThat(body.get("traceId").asText()).isEqualTo("corr-db-down");

        for (String secret : new String[] {"jdbc:", "127.0.0.1", "unreachable_db", "auth_app", PASSWORD, "SELECT", "system_user"}) {
            assertThat(response.getBody()).as("response body").doesNotContainIgnoringCase(secret);
            assertThat(output.getAll()).as("service log").doesNotContainIgnoringCase(secret);
        }
    }
}
