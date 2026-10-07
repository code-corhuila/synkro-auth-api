package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

public class RefreshUseCase {
    private final UserRepository userRepository;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final HashFunction hashFunction;

    public RefreshUseCase(UserRepository userRepository, TokenIssuer tokenIssuer,
                          RefreshTokenStore refreshTokenStore, HashFunction hashFunction) {
        this.userRepository = userRepository;
        this.tokenIssuer = tokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
        this.hashFunction = hashFunction;
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
        refreshTokenStore.save(hashFunction.hash(newRefreshToken), user.getUserId());

        return new LoginResult(newAccessToken, newRefreshToken);
    }
}
