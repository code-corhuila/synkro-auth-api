package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore.Consumption;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

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
        // The replacement exists before the old token is burned and both change in one store step. Burning first and
        // saving later would let a reuse detected in between revoke everything except the replacement saved after it.
        String newRefreshToken = tokenIssuer.issueRefreshToken();
        String newRefreshTokenHash = hashFunction.hash(newRefreshToken);
        String userId = switch (refreshTokenStore.rotate(
            hashFunction.hash(refreshToken), newRefreshTokenHash, clock.instant().plus(refreshTokenTtl))) {
            case Consumption.Consumed consumed -> consumed.userId();
            case Consumption.AlreadyUsed used -> {
                // A replay means the token was copied (or submitted twice): the safe answer ends every session of its owner.
                refreshTokenStore.revokeAllOf(used.userId());
                throw new InvalidCredentialsException();
            }
            case Consumption.Unknown unknown -> throw new InvalidCredentialsException();
        };

        Optional<SystemUser> user = userRepository.findById(userId).filter(SystemUser::isActive);
        if (user.isEmpty()) {
            // The owner cannot refresh: the replacement was stored with the rotation and is never handed out, so it must not stay usable.
            refreshTokenStore.revoke(newRefreshTokenHash, userId);
            throw new InvalidCredentialsException();
        }

        String newAccessToken = tokenIssuer.issueAccessToken(user.get().getUserId(), user.get().getRole());
        return new LoginResult(newAccessToken, newRefreshToken);
    }
}
