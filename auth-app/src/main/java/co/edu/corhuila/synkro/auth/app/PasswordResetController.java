package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordCommand;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordResult;
import co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCase;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.io.IOException;
import java.util.List;

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
    private final ObjectMapper json;

    public PasswordResetController(ResetUserPasswordUseCase resetUserPassword, ObjectMapper json) {
        this.resetUserPassword = resetUserPassword;
        this.json = json;
    }

    @PostMapping("/users/{id}/password-reset")
    public ResponseEntity<PasswordResetResponse> reset(@AuthenticationPrincipal AuthenticatedCaller caller,
                                                       HttpServletRequest http,
                                                       @PathVariable("id") String id,
                                                       @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey)
            throws HttpMediaTypeNotSupportedException {
        resetUserPassword.authorizeBeforeDecoding(caller, CorrelationIdFilter.idOf(http));
        JsonNode body = readBody(http);
        ResetUserPasswordResult result = resetUserPassword.execute(caller, CorrelationIdFilter.idOf(http),
            new ResetUserPasswordCommand(id, idempotencyKey, text(body, "newPassword"), text(body, "confirmPassword")));
        // A reset answer is about a credential change: it is never cached, a replay's included.
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(PasswordResetResponse.of(result));
    }

    // Reading JSON through an MVC argument converter would answer 400/415 before the authorization policy runs.
    private JsonNode readBody(HttpServletRequest http) throws HttpMediaTypeNotSupportedException {
        try {
            byte[] input = http.getInputStream().readAllBytes();
            if (input.length == 0) {
                throw new HttpMessageNotReadableException("Missing JSON body", new ServletServerHttpRequest(http));
            }
            MediaType contentType;
            try {
                contentType = http.getContentType() == null ? MediaType.APPLICATION_OCTET_STREAM
                    : MediaType.parseMediaType(http.getContentType());
            } catch (InvalidMediaTypeException invalid) {
                throw new HttpMediaTypeNotSupportedException(MediaType.APPLICATION_OCTET_STREAM, List.of(MediaType.APPLICATION_JSON));
            }
            if (!MediaType.APPLICATION_JSON.includes(contentType)
                    && !new MediaType("application", "*+json").includes(contentType)) {
                throw new HttpMediaTypeNotSupportedException(contentType, List.of(MediaType.APPLICATION_JSON));
            }
            JsonNode body = json.readTree(input);
            if (body == null || body.isMissingNode()) {
                throw new HttpMessageNotReadableException("Missing JSON body", new ServletServerHttpRequest(http));
            }
            return body;
        } catch (IOException failure) {
            throw new HttpMessageNotReadableException("Invalid JSON body", failure, new ServletServerHttpRequest(http));
        }
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
