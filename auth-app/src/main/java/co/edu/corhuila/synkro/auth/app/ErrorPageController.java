package co.edu.corhuila.synkro.auth.app;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * What the servlet container renders at /error after {@code sendError} or an exception that escaped a filter:
 * the same envelope, built from the status the container recorded. Replaces Spring Boot's default error body.
 * The ERROR dispatch is the only one SecurityConfig lets through; a direct request to /error stays a 401.
 */
@RestController
public class ErrorPageController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<Map<String, Object>> error(HttpServletRequest request) {
        Object recorded = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        int status = recorded instanceof Integer code ? code : HttpStatus.NOT_FOUND.value();
        HttpStatus resolved = HttpStatus.resolve(status);
        return ResponseEntity.status(resolved != null ? resolved : HttpStatus.INTERNAL_SERVER_ERROR)
            .contentType(ApiError.CONTENT_TYPE)
            .body(ApiError.body(ApiError.codeFor(status), ApiError.messageFor(status), null, request));
    }
}
