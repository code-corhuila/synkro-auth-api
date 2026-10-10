package co.edu.corhuila.synkro.auth.app;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/**
 * Answers the 401 and 403 raised inside the security filter chain, where
 * {@link ApiExceptionHandler} cannot reach, with the same envelope and the request's correlation id.
 */
class SecurityErrorResponses {
    static final String UNAUTHORIZED_MESSAGE = "Missing or invalid authentication token";
    static final String FORBIDDEN_MESSAGE = "The authenticated caller is not allowed to perform this operation";

    private final ObjectMapper json;

    SecurityErrorResponses(ObjectMapper json) {
        this.json = json;
    }

    AuthenticationEntryPoint entryPoint() {
        return (request, response, e) -> write(request, response, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", UNAUTHORIZED_MESSAGE);
    }

    AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> write(request, response, HttpStatus.FORBIDDEN, "FORBIDDEN", FORBIDDEN_MESSAGE);
    }

    private void write(HttpServletRequest request, HttpServletResponse response, HttpStatus status, String error, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(ApiError.CONTENT_TYPE.toString());
        json.writeValue(response.getWriter(), ApiError.body(error, message, null, request));
    }
}
