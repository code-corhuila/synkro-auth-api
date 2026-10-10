package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.GetUserUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.RegisterUserCommand;
import co.edu.corhuila.synkro.auth.application.usecase.RegisterUserResult;
import co.edu.corhuila.synkro.auth.application.usecase.RegisterUserUseCase;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.time.Instant;

/**
 * registerUser and getUser of synkro-auth-api.yaml. The controller only translates HTTP into a command and a
 * result back into HTTP: validation and the role decision belong to the use cases.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class UserController {

    public record RegisterRequest(String name, String email, String password, String role) {}

    /** Mirrors UserResponse: system_user without the password hash. */
    public record UserResponse(String userId, String name, String email, String role, Instant registrationDate, boolean active) {
        static UserResponse of(SystemUser user) {
            return new UserResponse(user.getUserId(), user.getName(), user.getEmail(), user.getRole(),
                user.getRegistrationDate(), user.isActive());
        }
    }

    private final RegisterUserUseCase registerUser;
    private final GetUserUseCase getUser;

    public UserController(RegisterUserUseCase registerUser, GetUserUseCase getUser) {
        this.registerUser = registerUser;
        this.getUser = getUser;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
                                                 @RequestBody RegisterRequest request) {
        RegisterUserResult result = registerUser.execute(new RegisterUserCommand(
            idempotencyKey, request.name(), request.email(), request.password(), request.role()));
        UserResponse body = UserResponse.of(result.user());
        return result.created()
            ? ResponseEntity.created(URI.create("/api/v1/auth/users/" + body.userId())).body(body)
            : ResponseEntity.ok(body);
    }

    @GetMapping("/users/{id}")
    public UserResponse get(@AuthenticationPrincipal AuthenticatedCaller caller, @PathVariable("id") String id) {
        return UserResponse.of(getUser.execute(caller, id));
    }
}
