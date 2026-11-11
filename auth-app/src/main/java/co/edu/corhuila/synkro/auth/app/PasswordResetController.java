package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordCommand;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordResult;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCase;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/**
 * resetUserPassword of ADR-021 (HU-AUTH-19): an ADMIN replaces the password of another user. The controller only
 * translates HTTP into a command and a result back into HTTP: validation, the role decision and every rule about the
 * target belong to the use case. The actor is the verified token's subject; the body can name nobody.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class PasswordResetController {

    /** The response carries no secret: not the password, not a hash, not a token. */
    public record PasswordResetResponse(String userId, Instant passwordResetAt) {
        static PasswordResetResponse of(ResetUserPasswordResult result) {
            return new PasswordResetResponse(result.userId(), result.passwordResetAt());
        }
    }

    private final ResetUserPasswordUseCase resetUserPassword;

    public PasswordResetController(ResetUserPasswordUseCase resetUserPassword) {
        this.resetUserPassword = resetUserPassword;
    }

    @PostMapping("/users/{id}/password-reset")
    public ResponseEntity<PasswordResetResponse> reset(@AuthenticationPrincipal AuthenticatedCaller caller,
                                                       HttpServletRequest http,
                                                       @PathVariable("id") String id,
                                                       @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
                                                       @RequestBody JsonNode body) {
        ResetUserPasswordResult result = resetUserPassword.execute(caller, CorrelationIdFilter.idOf(http),
            new ResetUserPasswordCommand(id, idempotencyKey, text(body, "newPassword"), text(body, "confirmPassword")));
        // A reset answer is about a credential change: it is never cached, a replay's included.
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(PasswordResetResponse.of(result));
    }

    // Anything that is not a JSON string is "not there": a number is never turned into a password, and the use case
    // reports the field as missing. Fields the contract does not name are ignored, and none can name an actor.
    private static String text(JsonNode body, String field) {
        if (body == null || !body.isObject()) {
            return null;
        }
        JsonNode value = body.get(field);
        return value != null && value.isTextual() ? value.textValue() : null;
    }
}
