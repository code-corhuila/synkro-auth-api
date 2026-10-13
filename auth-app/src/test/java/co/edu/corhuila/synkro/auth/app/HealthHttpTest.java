package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/** The two answers of GET /health (cross-cutting.md section 4), with the schema check replaced by a switch. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(HealthHttpTest.Switch.class)
class HealthHttpTest {

    private static final AtomicBoolean SCHEMA_REACHABLE = new AtomicBoolean(true);

    @TestConfiguration
    static class Switch {
        @Bean
        @Primary
        DatabaseHealthProbe switchableDatabase() {
            return SCHEMA_REACHABLE::get;
        }
    }

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("health-http-test");
        registry.add("JWT_PRIVATE_KEY_FILE", TestKeys.writePrivateKeyPem(TestKeys.generate(2048), dir)::toString);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate http = new TestRestTemplate();
    private final ObjectMapper json = new ObjectMapper();

    @AfterEach
    void restore() {
        SCHEMA_REACHABLE.set(true);
    }

    private ResponseEntity<String> health(HttpHeaders headers) {
        return http.exchange("http://localhost:" + port + "/health", HttpMethod.GET, new HttpEntity<>(headers), String.class);
    }

    @Test
    void whenTheSchemaIsReachable_itIs200Ok_withTheDependencyListed() throws Exception {
        ResponseEntity<String> response = health(new HttpHeaders());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode body = json.readTree(response.getBody());
        assertThat(body.get("status").asText()).isEqualTo("ok");
        assertThat(body.get("service").asText()).isEqualTo("synkro-auth-api");
        assertThat(body.get("timestamp").asText()).isNotBlank();
        assertThat(body.get("dependencies").get("database").asText()).isEqualTo("ok");
    }

    @Test
    void whenTheSchemaIsNotReachable_itIs503Degraded_withTheDependencyDown() throws Exception {
        SCHEMA_REACHABLE.set(false);

        ResponseEntity<String> response = health(new HttpHeaders());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
        JsonNode body = json.readTree(response.getBody());
        assertThat(body.get("status").asText()).isEqualTo("degraded");
        assertThat(body.get("service").asText()).isEqualTo("synkro-auth-api");
        assertThat(body.get("timestamp").asText()).isNotBlank();
        assertThat(body.get("dependencies").get("database").asText()).isEqualTo("down");
    }

    @Test
    void itStaysPublic_whateverTheAuthorizationHeaderSays() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer not-a-token");

        assertThat(health(headers).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void itEchoesTheCorrelationIdLikeEveryOtherRoute() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Correlation-Id", "corr-health-1");

        assertThat(health(headers).getHeaders().getFirst("X-Correlation-Id")).isEqualTo("corr-health-1");
    }
}
