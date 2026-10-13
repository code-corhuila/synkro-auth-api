package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.LogoutUseCase;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * logout of synkro-auth-api.yaml. Protected by the filter chain (any valid access token); which roles may
 * call it, and what the body must contain, are decided by the use case.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class LogoutController {

    /** Mirrors LogoutResponse. */
    public record LogoutResponse(boolean loggedOut) {}

    private final LogoutUseCase logoutUseCase;

    public LogoutController(LogoutUseCase logoutUseCase) {
        this.logoutUseCase = logoutUseCase;
    }

    @PostMapping("/logout")
    public LogoutResponse logout(@AuthenticationPrincipal AuthenticatedCaller caller,
                                 @RequestBody AuthController.RefreshRequest request) {
        return new LogoutResponse(logoutUseCase.execute(caller, request.refreshToken()).loggedOut());
    }
}
