package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Fast HTTP tests that need no database import this to replace the two persistence ports
 * with in-memory fakes. Tests against PostgreSQL do not.
 */
@TestConfiguration
class InMemoryAdaptersTestConfig {

    @Bean
    @Primary
    UserRepository fakeUserRepository() {
        return new FakeUserRepository();
    }

    @Bean
    @Primary
    RefreshTokenStore fakeRefreshTokenStore() {
        return new FakeRefreshTokenStore();
    }
}
