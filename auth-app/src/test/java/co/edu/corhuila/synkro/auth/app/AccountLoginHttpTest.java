package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.memory.MemoryLoginAttempts;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.*;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.*;
import org.springframework.http.*;
import org.springframework.test.context.*;
import java.nio.file.Files;
import java.time.*;
import java.util.Map;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({InMemoryAdaptersTestConfig.class,AccountLoginHttpTest.Time.class})
class AccountLoginHttpTest {
    @DynamicPropertySource static void key(DynamicPropertyRegistry registry) throws Exception {
        var file=TestKeys.writePrivateKeyPem(TestKeys.generate(2048),Files.createTempDirectory("account-login-key"));
        registry.add("JWT_PRIVATE_KEY_FILE",file::toString);
    }
    @LocalServerPort int port;
    @Autowired MutableClock clock;
    @Autowired MemoryLoginAttempts attempts;
    @Autowired LoginAttemptsCleanup cleanup;
    final TestRestTemplate http=new TestRestTemplate();
    ResponseEntity<String> login(String email,String password,int source) {
        var headers=new HttpHeaders();headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Forwarded-For","192.0.2."+source);headers.set("X-Correlation-Id","account-login-case");
        return http.postForEntity("http://localhost:"+port+"/api/v1/auth/login",
            new HttpEntity<>(Map.of("email",email,"password",password),headers),String.class);
    }
    @Test void directAuthCombinesSourceAddressesAndReturnsTheDocumentedEnvelopeWithoutExtendingExpiry() {
        assertThat(login("admin@synkro.test","admin-dev-password",1).getStatusCode().value()).isEqualTo(200);
        for(String account: new String[]{"admin@synkro.test","unknown@synkro.test"}) {
            for(int source=1;source<=3;source++) {
                var result=login(source==2?" "+account.toUpperCase()+" ":account,"wrong",source);
                assertThat(result.getStatusCode().value()).isEqualTo(401);
                assertThat(result.getBody()).doesNotContain("accessToken","refreshToken");
            }
            var rejected=login(account,"admin-dev-password",4);
            assertThat(rejected.getStatusCode().value()).isEqualTo(429);
            assertThat(rejected.getHeaders().getFirst("Retry-After")).isEqualTo("30");
            assertThat(rejected.getHeaders().getFirst("Cache-Control")).isEqualTo("no-store");
            assertThat(rejected.getHeaders().getFirst("X-Correlation-Id")).isEqualTo("account-login-case");
            assertThat(rejected.getBody()).contains("TOO_MANY_REQUESTS","traceId").doesNotContain(account,"accessToken","refreshToken");
        }
        clock.advance(Duration.ofMillis(29_100));
        var lastSecond=login("admin@synkro.test","admin-dev-password",5);
        assertThat(lastSecond.getStatusCode().value()).isEqualTo(429);
        assertThat(lastSecond.getHeaders().getFirst("Retry-After")).isEqualTo("1");
        clock.advance(Duration.ofMillis(900));
        assertThat(login("admin@synkro.test","admin-dev-password",6).getStatusCode().value()).isEqualTo(200);
        assertThat(attempts.retainedAccounts()).isEqualTo(1); // unknown account only
        clock.advance(Duration.ofSeconds(570));cleanup.removeExpired();
        assertThat(attempts.retainedAccounts()).isZero();
    }
    @TestConfiguration static class Time {
        @Bean @Primary MutableClock controlledClock(){return new MutableClock();}
    }
    static final class MutableClock extends Clock {
        volatile Instant time=Instant.now();
        public Instant instant(){return time;}
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        void advance(Duration duration){time=time.plus(duration);}
    }
}
