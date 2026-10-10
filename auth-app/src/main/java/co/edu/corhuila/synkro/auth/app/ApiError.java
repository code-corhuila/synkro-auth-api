package co.edu.corhuila.synkro.auth.app;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The common error envelope of cross-cutting.md §1: { error, message, details?, traceId }. */
final class ApiError {
    static final MediaType CONTENT_TYPE = new MediaType(MediaType.APPLICATION_JSON, StandardCharsets.UTF_8);

    private ApiError() {}

    static Map<String, Object> body(String error, String message, List<?> details, HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("message", message);
        if (details != null) {
            body.put("details", details);
        }
        body.put("traceId", CorrelationIdFilter.idOf(request));
        return body;
    }

    /**
     * The closed catalog of 07-api/guidelines.md has no code for 405 or 415, so every client error other than
     * 404 is a VALIDATION_ERROR: the request itself is what is wrong.
     */
    static String codeFor(int status) {
        if (status == 404) {
            return "NOT_FOUND";
        }
        return status >= 500 ? "INTERNAL_ERROR" : "VALIDATION_ERROR";
    }

    /** Fixed messages: nothing the framework says about the failure reaches the client. */
    static String messageFor(int status) {
        return switch (status) {
            case 404 -> "Resource not found";
            case 405 -> "Method not allowed";
            case 406 -> "Not acceptable";
            case 415 -> "Unsupported media type";
            default -> status >= 500 ? "The request could not be completed" : "The request is not valid";
        };
    }
}
