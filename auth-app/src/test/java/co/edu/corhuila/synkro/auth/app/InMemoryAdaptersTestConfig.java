package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory.InMemoryRefreshTokenStore;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory.InMemorySeededUserRepository;
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
    UserRepository inMemoryUserRepository() {
        return new InMemorySeededUserRepository(new BcryptPasswordHasher());
    }

    @Bean
    @Primary
    RefreshTokenStore inMemoryRefreshTokenStore() {
        return new InMemoryRefreshTokenStore();
    }
}
