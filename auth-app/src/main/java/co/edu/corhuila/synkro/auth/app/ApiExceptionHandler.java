package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.ForbiddenException;
import co.edu.corhuila.synkro.auth.application.usecase.InvalidCredentialsException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

/** Maps exceptions to the standard error envelope of cross-cutting.md §1. */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    public record FieldProblem(String field, String message) {}

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, Object>> invalidCredentials(HttpServletRequest request) {
        // One fixed message for every cause: the response must never say whether the
        // email exists, the account is inactive, or the password was wrong.
        return envelope(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Invalid credentials", null, request);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<Map<String, Object>> forbidden(ForbiddenException e, HttpServletRequest request) {
        return envelope(HttpStatus.FORBIDDEN, "FORBIDDEN", e.getMessage(), null, request);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<Map<String, Object>> databaseFailure(DataAccessException e, HttpServletRequest request) {
        // The exception's message and causes carry the SQL text, the host and the user, so only
        // its type and SQLSTATE (a five-character code such as 08001 or 42501) are logged.
        log.error("Database failure traceId={} type={} sqlState={}",
            CorrelationIdFilter.idOf(request), e.getClass().getSimpleName(), sqlStateOf(e));
        return envelope(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "The request could not be completed", null, request);
    }

    private static String sqlStateOf(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t instanceof SQLException sql && sql.getSQLState() != null) {
                return sql.getSQLState();
            }
        }
        return "unknown";
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
        return ResponseEntity.status(status).contentType(ApiError.CONTENT_TYPE).body(ApiError.body(error, message, details, request));
    }
}
