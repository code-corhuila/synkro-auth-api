package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.port.out.CredentialIssuanceStore;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
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

    /** The in-memory tests have no database to ask: the schema counts as reachable. */
    @Bean
    @Primary
    DatabaseHealthProbe reachableDatabase() {
        return () -> true;
    }

    @Bean
    @Primary
    RefreshTokenStore fakeRefreshTokenStore() {
        return new FakeRefreshTokenStore();
    }

    /** The same contract as the real port, over the in-memory users and refresh tokens. */
    @Bean
    @Primary
    CredentialIssuanceStore fakeCredentialIssuanceStore(UserRepository users, RefreshTokenStore refreshTokens) {
        return (userId, verifiedPasswordHash, refreshTokenHash, expiresAt) -> {
            java.util.Optional<SystemUser> current = users.findById(userId)
                .filter(SystemUser::isActive)
                .filter(u -> u.getPasswordHash().equals(verifiedPasswordHash));
            current.ifPresent(u -> refreshTokens.save(refreshTokenHash, userId, expiresAt));
            return current;
        };
    }

    /** Declared with its own type so a test can inject it and read what the use case handed over. */
    @Bean
    @Primary
    FakePasswordResetStore fakePasswordResetStore() {
        return new FakePasswordResetStore();
    }
}
