package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.RefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;

import java.util.List;

public class LogoutUseCase {
    private final RefreshTokenStore refreshTokenStore;
    private final HashFunction hashFunction;

    public LogoutUseCase(RefreshTokenStore refreshTokenStore, HashFunction hashFunction) {
        this.refreshTokenStore = refreshTokenStore;
        this.hashFunction = hashFunction;
    }

    public LogoutResult execute(AuthenticatedCaller caller, String refreshToken) {
        RoleGuard.requireAnyRole(caller, "log out", Roles.ADMIN, Roles.SALESPERSON, Roles.INVENTORY);
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ValidationException(List.of(new Problem("refreshToken", "The field refreshToken is required")));
        }
        // Whatever the store finds, the answer is the same: it must not reveal whether the token exists or whose it is.
        refreshTokenStore.revoke(hashFunction.hash(refreshToken), caller.subject());
        return new LogoutResult(true);
    }
}
