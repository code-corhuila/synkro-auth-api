package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256TokenIssuer;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256TokenVerifier;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory.InMemoryRefreshTokenStore;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory.InMemorySeededUserRepository;
import co.edu.corhuila.synkro.auth.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.application.usecase.LoginUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.RefreshUseCase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;

@Configuration
public class AuthBeansConfig {

    private static final Logger log = LoggerFactory.getLogger(AuthBeansConfig.class);

    // Declared as the concrete type: the seeded-user adapter needs hash(), which the
    // PasswordHasher port (verify-only) deliberately lacks. Use cases still see only the port.
    @Bean
    public BcryptPasswordHasher passwordHasher() {
        return new BcryptPasswordHasher();
    }

    @Bean
    public HashFunction hashFunction() {
        return new Sha256HashFunction();
    }

    // access token 1 hour (07-api/authentication.md); overridable, never longer by default.
    @Bean
    public TokenIssuer tokenIssuer(PrivateKey jwtPrivateKey,
                                   @Value("${synkro.auth.access-token-ttl:PT1H}") Duration accessTokenTtl) {
        return new Rs256TokenIssuer(jwtPrivateKey, accessTokenTtl);
    }

    // The public key is derived from the signing key (KeyLoader.publicKeyFor): this service
    // verifies exactly what it signs, with no second variable that could disagree.
    @Bean
    public AccessTokenVerifier accessTokenVerifier(PrivateKey jwtPrivateKey) {
        return new Rs256TokenVerifier(KeyLoader.publicKeyFor(jwtPrivateKey), Clock.systemUTC());
    }

    // ── TEMPORARY in-memory adapters ─────────────────────────────────
    // Replaced by Postgres adapters once synkro-auth-db has system_user and refresh_token
    // tables (follow-up story). Until then the service has three seeded development users
    // whose passwords are public in the README: it must not be deployed anywhere real.

    @Bean
    public UserRepository userRepository(BcryptPasswordHasher hasher) {
        log.warn("TEMPORARY in-memory seeded users are active (admin/sales/inventory @synkro.test). "
            + "Development only: replaced by a Postgres adapter when system_user exists.");
        return new InMemorySeededUserRepository(hasher);
    }

    @Bean
    public RefreshTokenStore refreshTokenStore() {
        return new InMemoryRefreshTokenStore();
    }

    // ── Use cases ────────────────────────────────────────────────────

    @Bean
    public LoginUseCase loginUseCase(UserRepository users, PasswordHasher hasher, TokenIssuer issuer,
                                     RefreshTokenStore store, HashFunction hash) {
        return new LoginUseCase(users, hasher, issuer, store, hash);
    }

    @Bean
    public RefreshUseCase refreshUseCase(UserRepository users, TokenIssuer issuer,
                                         RefreshTokenStore store, HashFunction hash) {
        return new RefreshUseCase(users, issuer, store, hash);
    }
}
