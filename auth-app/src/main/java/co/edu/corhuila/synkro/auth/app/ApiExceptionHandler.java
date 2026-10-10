package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.application.usecase.ForbiddenException;
import co.edu.corhuila.synkro.auth.application.usecase.InvalidCredentialsException;
import co.edu.corhuila.synkro.auth.application.usecase.NotFoundException;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.sql.SQLException;
import java.util.List;
import java.util.Map;

/**
 * Maps every exception that reaches the MVC layer to the standard error envelope of cross-cutting.md §1.
 * The response is written in the original dispatch: nothing is sent through the servlet error page, so the
 * security chain is not consulted a second time (see the ERROR rule in SecurityConfig). The framework's own
 * exceptions (unknown route, wrong method, unsupported media type...) are covered by extending
 * {@link ResponseEntityExceptionHandler}, whose default ProblemDetail body is replaced below.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

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

    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<Map<String, Object>> invalidInput(ValidationException e, HttpServletRequest request) {
        return envelope(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", e.problems().get(0).message(), e.problems(), request);
    }

    @ExceptionHandler(BusinessRuleViolationException.class)
    public ResponseEntity<Map<String, Object>> businessRule(BusinessRuleViolationException e, HttpServletRequest request) {
        return envelope(HttpStatus.UNPROCESSABLE_ENTITY, "BUSINESS_RULE_VIOLATION", e.getMessage(),
            List.of(new FieldProblem(e.field(), e.getMessage())), request);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(NotFoundException e, HttpServletRequest request) {
        return envelope(HttpStatus.NOT_FOUND, "NOT_FOUND", e.getMessage(), null, request);
    }

    @ExceptionHandler(RequestValidationException.class)
    public ResponseEntity<Map<String, Object>> validation(RequestValidationException e, HttpServletRequest request) {
        return envelope(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", e.problems().get(0).message(), e.problems(), request);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<Map<String, Object>> databaseFailure(DataAccessException e, HttpServletRequest request) {
        // The exception's message and causes carry the SQL text, the host and the user, so only
        // its type and SQLSTATE (a five-character code such as 08001 or 42501) are logged.
        log.error("Database failure traceId={} type={} sqlState={}",
            CorrelationIdFilter.idOf(request), e.getClass().getSimpleName(), sqlStateOf(e));
        return internalError(request);
    }

    // These two are answered by the security chain when they arise in a filter. Raised from a controller
    // they would otherwise fall into the catch-all below and turn a 401 or a 403 into a 500.
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> accessDenied(HttpServletRequest request) {
        return envelope(HttpStatus.FORBIDDEN, "FORBIDDEN", SecurityErrorResponses.FORBIDDEN_MESSAGE, null, request);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> authenticationFailed(HttpServletRequest request) {
        return envelope(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", SecurityErrorResponses.UNAUTHORIZED_MESSAGE, null, request);
    }

    /** The catch-all: the client gets a generic message, the log keeps the cause. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> unexpected(Exception e, HttpServletRequest request) {
        log.error("Unexpected failure traceId={}", CorrelationIdFilter.idOf(request), e);
        return internalError(request);
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException e, HttpHeaders headers,
                                                                  HttpStatusCode status, WebRequest request) {
        return frameworkError(HttpStatus.BAD_REQUEST, "The request body is missing or is not valid JSON", headers, request);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception e, Object body, HttpHeaders headers,
                                                             HttpStatusCode status, WebRequest request) {
        HttpStatus resolved = HttpStatus.resolve(status.value());
        return frameworkError(resolved != null ? resolved : HttpStatus.INTERNAL_SERVER_ERROR,
            ApiError.messageFor(status.value()), headers, request);
    }

    private ResponseEntity<Object> frameworkError(HttpStatus status, String message, HttpHeaders headers, WebRequest request) {
        HttpServletRequest servletRequest = ((ServletWebRequest) request).getRequest();
        HttpHeaders out = new HttpHeaders();
        out.putAll(headers);
        out.setContentType(ApiError.CONTENT_TYPE);
        return ResponseEntity.status(status).headers(out)
            .body(ApiError.body(ApiError.codeFor(status.value()), message, null, servletRequest));
    }

    private static ResponseEntity<Map<String, Object>> internalError(HttpServletRequest request) {
        return envelope(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", ApiError.messageFor(500), null, request);
    }

    private static String sqlStateOf(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t instanceof SQLException sql && sql.getSQLState() != null) {
                return sql.getSQLState();
            }
        }
        return "unknown";
    }

    private static ResponseEntity<Map<String, Object>> envelope(HttpStatus status, String error, String message,
                                                               List<?> details, HttpServletRequest request) {
        return ResponseEntity.status(status).contentType(ApiError.CONTENT_TYPE).body(ApiError.body(error, message, details, request));
    }
}
