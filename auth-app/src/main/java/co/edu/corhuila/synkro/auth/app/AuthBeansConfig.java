package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256TokenIssuer;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256TokenVerifier;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcRefreshTokenStore;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcUserRepository;
import co.edu.corhuila.synkro.auth.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.application.usecase.LoginUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.RefreshUseCase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;

@Configuration
public class AuthBeansConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public PasswordHasher passwordHasher() {
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
    public AccessTokenVerifier accessTokenVerifier(PrivateKey jwtPrivateKey, Clock clock) {
        return new Rs256TokenVerifier(KeyLoader.publicKeyFor(jwtPrivateKey), clock);
    }

    @Bean
    public UserRepository userRepository(JdbcTemplate jdbc) {
        return new JdbcUserRepository(jdbc);
    }

    @Bean
    public RefreshTokenStore refreshTokenStore(JdbcTemplate jdbc) {
        return new JdbcRefreshTokenStore(jdbc);
    }

    // ── Use cases ────────────────────────────────────────────────────

    @Bean
    public LoginUseCase loginUseCase(UserRepository users, PasswordHasher hasher, TokenIssuer issuer,
                                     RefreshTokenStore store, HashFunction hash, Clock clock,
                                     @Value("${synkro.auth.refresh-token-ttl:P7D}") Duration refreshTokenTtl) {
        return new LoginUseCase(users, hasher, issuer, store, hash, clock, refreshTokenTtl);
    }

    @Bean
    public RefreshUseCase refreshUseCase(UserRepository users, TokenIssuer issuer,
                                         RefreshTokenStore store, HashFunction hash, Clock clock,
                                         @Value("${synkro.auth.refresh-token-ttl:P7D}") Duration refreshTokenTtl) {
        return new RefreshUseCase(users, issuer, store, hash, clock, refreshTokenTtl);
    }
}
