package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;

public class LogoutUseCase {
    private final RefreshTokenStore refreshTokenStore;
    private final HashFunction hashFunction;

    public LogoutUseCase(RefreshTokenStore refreshTokenStore, HashFunction hashFunction) {
        this.refreshTokenStore = refreshTokenStore;
        this.hashFunction = hashFunction;
    }

    public LogoutResult execute(AuthenticatedCaller caller, String refreshToken) {
        return new LogoutResult(false);
    }
}
