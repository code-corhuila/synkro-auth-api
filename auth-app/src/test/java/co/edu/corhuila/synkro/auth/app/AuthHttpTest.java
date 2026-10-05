package co.edu.corhuila.synkro.auth.app;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthHttpTest {

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
}
