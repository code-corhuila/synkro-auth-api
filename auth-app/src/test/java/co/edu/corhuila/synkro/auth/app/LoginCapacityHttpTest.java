package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import java.net.URI;
import java.net.http.*;
import java.nio.file.Files;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"synkro.auth.login-max-concurrent=2", "synkro.auth.login-overload-retry-seconds=1"})
@Import(LoginCapacityHttpTest.Adapters.class)
class LoginCapacityHttpTest {
    @DynamicPropertySource static void key(DynamicPropertyRegistry registry) throws Exception {
        var file = TestKeys.writePrivateKeyPem(TestKeys.generate(2048), Files.createTempDirectory("capacity-key"));
        registry.add("JWT_PRIVATE_KEY_FILE", file::toString);
    }
    @LocalServerPort int port;
    @Autowired ControlledHasher hasher;
    @Autowired UserRepository users;
    private final HttpClient http = HttpClient.newHttpClient();

    HttpRequest request(String account, String password) {
        return HttpRequest.newBuilder(URI.create("http://localhost:"+port+"/api/v1/auth/login"))
            .timeout(Duration.ofSeconds(15)).header("Content-Type", "application/json")
            .header("X-Correlation-Id", "capacity-http")
            .POST(HttpRequest.BodyPublishers.ofString("{\"email\":\""+account+"\",\"password\":\""+password+"\"}"))
            .build();
    }
    HttpResponse<String> login(String account, String password) throws Exception {
        return http.send(request(account,password), HttpResponse.BodyHandlers.ofString());
    }

    @Test void realHttpRejectsExcessWorkBeforeLookupAndRetainsDisconnectedHolders() throws Exception {
        hasher.prepare(); clearInvocations(users);
        var one = http.sendAsync(request("admin@synkro.test","admin-dev-password"),HttpResponse.BodyHandlers.ofString());
        var two = http.sendAsync(request("sales@synkro.test","sales-dev-password"),HttpResponse.BodyHandlers.ofString());
        try {
            assertThat(hasher.entered.await(10,TimeUnit.SECONDS)).isTrue();
            for(int i=0;i<3;i++) {
                var rejected=login("inventory@synkro.test","inventory-dev-password");
                assertThat(rejected.statusCode()).isEqualTo(429);
                assertThat(rejected.headers().firstValue("Retry-After")).contains("1");
                assertThat(rejected.headers().firstValue("X-Correlation-Id")).contains("capacity-http");
                assertThat(rejected.body()).contains("TOO_MANY_REQUESTS").doesNotContain("accessToken","refreshToken");
            }
            verify(users,times(2)).findByEmail(anyString());
            one.cancel(true);
            assertThat(login("inventory@synkro.test","inventory-dev-password").statusCode()).isEqualTo(429);
            assertThat(hasher.active.get()).isEqualTo(2);
        } finally { hasher.release.countDown(); }
        assertThat(two.get(10,TimeUnit.SECONDS).statusCode()).isEqualTo(200);
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(10);
        while(hasher.active.get()!=0 && System.nanoTime()<until) Thread.sleep(10);
        assertThat(hasher.active.get()).isZero();
        assertThat(login("inventory@synkro.test","inventory-dev-password").statusCode()).isEqualTo(200);
        assertThat(hasher.peak.get()).isEqualTo(2);
        System.out.println("AUTH279 requests=7 capacity=2 held=2 observed200=2 rejected429=4 cancelledClients=1 peakPasswordWork=2 recoveryStatus=200");
    }

    @Test void invalidCredentialsAndAdapterFailuresReleaseTheirSlots() throws Exception {
        hasher.prepare(); hasher.release.countDown();
        assertThat(login("admin@synkro.test","wrong").statusCode()).isEqualTo(401);
        hasher.fail=true;
        try { assertThat(login("admin@synkro.test","admin-dev-password").statusCode()).isEqualTo(500); }
        finally { hasher.fail=false; }
        assertThat(login("admin@synkro.test","admin-dev-password").statusCode()).isEqualTo(200);
        assertThat(hasher.active.get()).isZero();
    }

    static final class ControlledHasher implements PasswordHasher {
        final AtomicInteger active=new AtomicInteger(),peak=new AtomicInteger();
        volatile CountDownLatch entered=new CountDownLatch(2),release=new CountDownLatch(1);
        volatile boolean fail;
        void prepare(){active.set(0);peak.set(0);entered=new CountDownLatch(2);release=new CountDownLatch(1);fail=false;}
        public String hash(String value){return "controlled-test-hash";}
        public boolean matches(String value,String hash){
            int current=active.incrementAndGet();peak.accumulateAndGet(current,Math::max);entered.countDown();
            boolean interrupted=false;
            try {
                for(;;)try { if(!release.await(10,TimeUnit.SECONDS))throw new IllegalStateException("test barrier timed out");break; }
                catch(InterruptedException e){interrupted=true;}
                if(fail)throw new IllegalStateException("controlled password adapter failure");
                return value.endsWith("-dev-password");
            } finally {active.decrementAndGet();if(interrupted)Thread.currentThread().interrupt();}
        }
    }
    @TestConfiguration static class Adapters {
        @Bean @Primary ControlledHasher controlledHasher(){return new ControlledHasher();}
        @Bean @Primary UserRepository users(){return spy(new FakeUserRepository());}
        @Bean @Primary RefreshTokenStore refreshTokens(){return new FakeRefreshTokenStore();}
        @Bean @Primary CredentialIssuanceStore credentials(UserRepository users,RefreshTokenStore tokens){
            return new InMemoryAdaptersTestConfig().fakeCredentialIssuanceStore(users,tokens);
        }
        @Bean @Primary DatabaseHealthProbe healthy(){return ()->true;}
    }
}
