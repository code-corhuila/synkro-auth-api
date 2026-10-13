package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.LoginResult;
import co.edu.corhuila.synkro.auth.application.usecase.LoginUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.RefreshUseCase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Request/response shapes follow the LoginRequest, RefreshRequest and TokenPair schemas of synkro-auth-api.yaml. */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    public record LoginRequest(String email, String password) {}

    public record RefreshRequest(String refreshToken) {}

    public record TokenPairResponse(String accessToken, String refreshToken, String tokenType, long expiresIn) {}

    private final LoginUseCase loginUseCase;
    private final RefreshUseCase refreshUseCase;
    private final long expiresInSeconds;

    public AuthController(LoginUseCase loginUseCase, RefreshUseCase refreshUseCase,
                          @Value("${synkro.auth.access-token-ttl:PT1H}") Duration accessTokenTtl) {
        this.loginUseCase = loginUseCase;
        this.refreshUseCase = refreshUseCase;
        this.expiresInSeconds = accessTokenTtl.toSeconds();
    }

    @PostMapping("/login")
    public ResponseEntity<TokenPairResponse> login(@RequestBody LoginRequest request) {
        List<ApiExceptionHandler.FieldProblem> problems = new ArrayList<>();
        requireText(problems, "email", request.email());
        requireText(problems, "password", request.password());
        if (!problems.isEmpty()) {
            throw new RequestValidationException(problems);
        }
        return tokenPair(loginUseCase.execute(request.email(), request.password()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenPairResponse> refresh(@RequestBody RefreshRequest request) {
        List<ApiExceptionHandler.FieldProblem> problems = new ArrayList<>();
        requireText(problems, "refreshToken", request.refreshToken());
        if (!problems.isEmpty()) {
            throw new RequestValidationException(problems);
        }
        return tokenPair(refreshUseCase.execute(request.refreshToken()));
    }

    private ResponseEntity<TokenPairResponse> tokenPair(LoginResult result) {
        // RFC 6749 §5.1: a response carrying tokens must never be cached.
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())
            .body(new TokenPairResponse(result.accessToken(), result.refreshToken(), "Bearer", expiresInSeconds));
    }

    private static void requireText(List<ApiExceptionHandler.FieldProblem> problems, String field, String value) {
        if (value == null || value.isBlank()) {
            problems.add(new ApiExceptionHandler.FieldProblem(field, "The field " + field + " is required"));
        }
    }
}
