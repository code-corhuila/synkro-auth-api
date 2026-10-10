package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.Duration;

public class RefreshUseCase {
    private final UserRepository userRepository;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final HashFunction hashFunction;
    private final Clock clock;
    private final Duration refreshTokenTtl;

    public RefreshUseCase(UserRepository userRepository, TokenIssuer tokenIssuer,
                          RefreshTokenStore refreshTokenStore, HashFunction hashFunction,
                          Clock clock, Duration refreshTokenTtl) {
        this.userRepository = userRepository;
        this.tokenIssuer = tokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
        this.hashFunction = hashFunction;
        this.clock = clock;
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public LoginResult execute(String refreshToken) {
        if (refreshToken == null) {
            throw new InvalidCredentialsException();
        }
        // Consuming first is what makes a replayed token fail: the old one is gone
        // before any new token is issued.
        String userId = refreshTokenStore.consumeAndRotate(hashFunction.hash(refreshToken))
            .orElseThrow(InvalidCredentialsException::new);

        SystemUser user = userRepository.findById(userId)
            .filter(SystemUser::isActive)
            .orElseThrow(InvalidCredentialsException::new);

        String newAccessToken = tokenIssuer.issueAccessToken(user.getUserId(), user.getRole());
        String newRefreshToken = tokenIssuer.issueRefreshToken();
        refreshTokenStore.save(hashFunction.hash(newRefreshToken), user.getUserId(), clock.instant().plus(refreshTokenTtl));

        return new LoginResult(newAccessToken, newRefreshToken);
    }
}
