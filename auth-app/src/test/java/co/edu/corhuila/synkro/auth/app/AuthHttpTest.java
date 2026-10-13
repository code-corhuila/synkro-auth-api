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
    void protectedRoute_returns401WithNoToken() {
        ResponseEntity<String> response = restTemplate.getForEntity(url("/api/v1/users/anything"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).contains("\"error\":\"UNAUTHORIZED\"");
    }

    @Test
    void protectedRoute_withPresentButMalformedToken_reachesTheController() {
        // A well-formed-but-fake Bearer header must NOT be rejected by the
        // filter — the filter only checks presence, never validity. If it
        // reaches the placeholder controller, that controller answers 501,
        // proving the request got past the security gate.
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer not-a-real-token");
        ResponseEntity<String> response = restTemplate.exchange(
            url("/api/v1/users/anything"), HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_IMPLEMENTED);
    }

    @Test
    void protectedRoute_401BodyIsUtf8Json() {
        ResponseEntity<String> response = restTemplate.getForEntity(url("/api/v1/users/anything"), String.class);

        assertThat(response.getHeaders().getContentType()).isNotNull();
        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON)).isTrue();
        assertThat(response.getHeaders().getContentType().getCharset()).isEqualTo(java.nio.charset.StandardCharsets.UTF_8);
    }

    @Test
    void unknownRoute_withBearerToken_keepsItsRealErrorStatus() {
        // MVC errors are rendered through a second (ERROR) dispatch to /error.
        // That dispatch must not be re-authorized as anonymous, or every
        // 404/405/500 behind the gate gets masked as a 401.
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer not-a-real-token");
        ResponseEntity<String> response = restTemplate.exchange(
            url("/api/v1/does-not-exist"), HttpMethod.GET, new HttpEntity<>(headers), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void errorEndpoint_isNotDirectlyReachableWithoutToken() {
        ResponseEntity<String> response = restTemplate.getForEntity(url("/error"), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
