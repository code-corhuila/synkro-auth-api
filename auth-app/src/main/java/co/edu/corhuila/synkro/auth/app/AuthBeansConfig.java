package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256TokenIssuer;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Rs256TokenVerifier;
import co.edu.corhuila.synkro.auth.adapter.out.crypto.Sha256HashFunction;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcRefreshTokenStore;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcServiceTokenRepository;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcServiceTokenStore;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcUserRegistrationStore;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcUserRepository;
import co.edu.corhuila.synkro.auth.application.port.out.AccessTokenVerifier;
import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenRepository;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.application.usecase.GetServiceTokenUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.GetUserUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.IssueServiceTokenUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.LoginUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.LogoutUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.RefreshUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.RegisterUserUseCase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionOperations;

import java.security.PrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;

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
    public RefreshTokenStore refreshTokenStore(JdbcTemplate jdbc, PlatformTransactionManager transactionManager) {
        return new JdbcRefreshTokenStore(jdbc, transactionManager);
    }

    @Bean
    public IdGenerator idGenerator() {
        return () -> UUID.randomUUID().toString();
    }

    // The transaction is opened by the adapter, not by the use case, so auth-core stays free of Spring.
    @Bean
    public UserRegistrationStore userRegistrationStore(JdbcTemplate jdbc, TransactionOperations transactions) {
        return new JdbcUserRegistrationStore(jdbc, transactions);
    }

    // Same key as the access tokens, a separate signer: issuing a service token is not a reason to
    // change the class that Login and Refresh depend on.
    @Bean
    public ServiceTokenSigner serviceTokenSigner(PrivateKey jwtPrivateKey) {
        return new Rs256ServiceTokenSigner(jwtPrivateKey);
    }

    @Bean
    public ServiceTokenStore serviceTokenStore(JdbcTemplate jdbc, TransactionOperations transactions) {
        return new JdbcServiceTokenStore(jdbc, transactions);
    }

    @Bean
    public ServiceTokenRepository serviceTokenRepository(JdbcTemplate jdbc) {
        return new JdbcServiceTokenRepository(jdbc);
    }

    // ── Use cases ────────────────────────────────────────────────────

    @Bean
    public IssueServiceTokenUseCase issueServiceTokenUseCase(ServiceTokenStore tokens, ServiceTokenSigner signer,
                                                             IdGenerator ids, Clock clock) {
        return new IssueServiceTokenUseCase(tokens, signer, ids, clock);
    }

    @Bean
    public GetServiceTokenUseCase getServiceTokenUseCase(ServiceTokenRepository tokens) {
        return new GetServiceTokenUseCase(tokens);
    }

    @Bean
    public RegisterUserUseCase registerUserUseCase(UserRepository users, UserRegistrationStore registrations,
                                                   PasswordHasher hasher, IdGenerator ids, Clock clock) {
        return new RegisterUserUseCase(users, registrations, hasher, ids, clock);
    }

    @Bean
    public GetUserUseCase getUserUseCase(UserRepository users) {
        return new GetUserUseCase(users);
    }

    @Bean
    public LoginUseCase loginUseCase(UserRepository users, PasswordHasher hasher, TokenIssuer issuer,
                                     RefreshTokenStore store, HashFunction hash, Clock clock,
                                     @Value("${synkro.auth.refresh-token-ttl:P7D}") Duration refreshTokenTtl) {
        return new LoginUseCase(users, hasher, issuer, store, hash, clock, refreshTokenTtl);
    }

    @Bean
    public LogoutUseCase logoutUseCase(RefreshTokenStore store, HashFunction hash) {
        return new LogoutUseCase(store, hash);
    }

    @Bean
    public RefreshUseCase refreshUseCase(UserRepository users, TokenIssuer issuer,
                                         RefreshTokenStore store, HashFunction hash, Clock clock,
                                         @Value("${synkro.auth.refresh-token-ttl:P7D}") Duration refreshTokenTtl) {
        return new RefreshUseCase(users, issuer, store, hash, clock, refreshTokenTtl);
    }
}
