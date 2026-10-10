package co.edu.corhuila.synkro.auth.app;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Public routes and the ERROR dispatch. Everything about tokens, roles and the 401/403
 * envelope lives in {@link TokenAuthenticationHttpTest}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthHttpTest {

    @DynamicPropertySource
    static void signingKey(DynamicPropertyRegistry registry) throws Exception {
        Path dir = Files.createTempDirectory("auth-http-test");
        Path key = TestKeys.writePrivateKeyPem(TestKeys.generate(2048), dir);
        registry.add("JWT_PRIVATE_KEY_FILE", key::toString);
    }

    @LocalServerPort
    int port;

    private final TestRestTemplate restTemplate = new TestRestTemplate();

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    @Test
    void health_returnsOkWithNoToken() {
        ResponseEntity<String> response = restTemplate.getForEntity(url("/health"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"status\":\"ok\"");
        assertThat(response.getBody()).contains("\"service\":\"synkro-auth-api\"");
    }

    @Test
    void errorEndpoint_isNotDirectlyReachableWithoutToken() {
        ResponseEntity<String> response = restTemplate.getForEntity(url("/error"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
