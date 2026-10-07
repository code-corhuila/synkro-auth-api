package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.InvalidCredentialsException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Maps exceptions to the standard error envelope of cross-cutting.md §1. */
@RestControllerAdvice
public class ApiExceptionHandler {

    public record FieldProblem(String field, String message) {}

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, Object>> invalidCredentials(HttpServletRequest request) {
        // One fixed message for every cause: the response must never say whether the
        // email exists, the account is inactive, or the password was wrong.
        return envelope(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid credentials", null, request);
    }

    @ExceptionHandler(RequestValidationException.class)
    public ResponseEntity<Map<String, Object>> validation(RequestValidationException e, HttpServletRequest request) {
        return envelope(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", e.problems().get(0).message(), e.problems(), request);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> unreadableBody(HttpServletRequest request) {
        return envelope(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "The request body is missing or is not valid JSON", null, request);
    }

    private static ResponseEntity<Map<String, Object>> envelope(HttpStatus status, String error, String message,
                                                               List<FieldProblem> details, HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("message", message);
        if (details != null) {
            body.put("details", details);
        }
        body.put("traceId", CorrelationIdFilter.idOf(request));
        return ResponseEntity.status(status).body(body);
    }
}
