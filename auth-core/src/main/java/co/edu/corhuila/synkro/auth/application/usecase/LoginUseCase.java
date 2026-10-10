package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.Duration;

public class LoginUseCase {
    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final HashFunction hashFunction;
    private final Clock clock;
    private final Duration refreshTokenTtl;

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
    }

    public LoginResult execute(String email, String password) {
        SystemUser user = userRepository.findByEmail(email)
            .filter(SystemUser::isActive)
            .orElseThrow(InvalidCredentialsException::new);

        if (password == null || !passwordHasher.matches(password, user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        String accessToken = tokenIssuer.issueAccessToken(user.getUserId(), user.getRole());
        String refreshToken = tokenIssuer.issueRefreshToken();
        refreshTokenStore.save(hashFunction.hash(refreshToken), user.getUserId(), clock.instant().plus(refreshTokenTtl));

        return new LoginResult(accessToken, refreshToken);
    }
}
