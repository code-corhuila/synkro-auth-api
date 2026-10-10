package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.Emails;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

public class LoginUseCase {
    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final HashFunction hashFunction;
    private final Clock clock;
    private final Duration refreshTokenTtl;
    // Verified when there is no usable user, so that every failed login costs one bcrypt verification
    // at the same cost factor and its response time says nothing about which emails exist.
    private final String standInHash;

    public LoginUseCase(UserRepository userRepository, PasswordHasher passwordHasher, TokenIssuer tokenIssuer,
                        RefreshTokenStore refreshTokenStore, HashFunction hashFunction,
                        Clock clock, Duration refreshTokenTtl) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.tokenIssuer = tokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
        this.hashFunction = hashFunction;
        this.clock = clock;
        this.refreshTokenTtl = refreshTokenTtl;
        this.standInHash = passwordHasher.hash(UUID.randomUUID().toString());
    }

    public LoginResult execute(String email, String password) {
        Optional<SystemUser> found = userRepository.findByEmail(Emails.normalize(email));

        // The verification runs whatever the outcome of the lookup; the decision comes after it.
        String hashToVerify = found.map(SystemUser::getPasswordHash).orElse(standInHash);
        boolean passwordMatches = passwordHasher.matches(password == null ? "" : password, hashToVerify);

        SystemUser user = found
            .filter(SystemUser::isActive)
            .filter(u -> password != null && passwordMatches)
            .orElseThrow(InvalidCredentialsException::new);

        String accessToken = tokenIssuer.issueAccessToken(user.getUserId(), user.getRole());
        String refreshToken = tokenIssuer.issueRefreshToken();
        refreshTokenStore.save(hashFunction.hash(refreshToken), user.getUserId(), clock.instant().plus(refreshTokenTtl));

        return new LoginResult(accessToken, refreshToken);
    }
}
