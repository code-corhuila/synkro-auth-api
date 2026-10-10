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
}
