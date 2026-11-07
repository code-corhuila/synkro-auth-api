package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.GetUserUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.RegisterUserCommand;
import co.edu.corhuila.synkro.auth.application.usecase.RegisterUserResult;
import co.edu.corhuila.synkro.auth.application.usecase.RegisterUserUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.SearchUsersCommand;
import co.edu.corhuila.synkro.auth.application.usecase.SearchUsersResult;
import co.edu.corhuila.synkro.auth.application.usecase.SearchUsersUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException;
import com.fasterxml.jackson.databind.JsonNode;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.time.Instant;
import java.util.List;

/**
 * registerUser, getUser and searchUsers of synkro-auth-api.yaml. The controller only translates HTTP into a
 * command and a result back into HTTP: validation and the role decision belong to the use cases.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class UserController {

    public record RegisterRequest(String name, String email, String password, String role) {}

    /** Mirrors UserResponse: system_user without the password hash. */
    public record UserResponse(String userId, String name, String email, String role, Instant registrationDate, boolean active) {
        static UserResponse of(SystemUser user) {
            return new UserResponse(user.getUserId(), user.getName(), user.getEmail(), user.getRole(),
                user.getRegistrationDate(), user.isActive());
        }
    }

    /** Mirrors PageMeta of _shared.yaml. */
    public record PageMeta(int page, int limit, long total, long totalPages) {
        static PageMeta of(int page, int limit, long total) {
            return new PageMeta(page, limit, total, (total + limit - 1) / limit);
        }
    }

    public record SearchResponse(List<UserResponse> data, PageMeta meta) {
        static SearchResponse of(SearchUsersResult result) {
            return new SearchResponse(result.items().stream().map(UserResponse::of).toList(),
                PageMeta.of(result.page(), result.limit(), result.total()));
        }
    }

    private final RegisterUserUseCase registerUser;
    private final GetUserUseCase getUser;
    private final SearchUsersUseCase searchUsers;

    public UserController(RegisterUserUseCase registerUser, GetUserUseCase getUser, SearchUsersUseCase searchUsers) {
        this.registerUser = registerUser;
        this.getUser = getUser;
        this.searchUsers = searchUsers;
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@AuthenticationPrincipal AuthenticatedCaller caller,
                                                 HttpServletRequest http,
                                                 @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
                                                 @RequestBody RegisterRequest request) {
        RegisterUserResult result = registerUser.execute(caller, CorrelationIdFilter.idOf(http), new RegisterUserCommand(
            idempotencyKey, request.name(), request.email(), request.password(), request.role()));
        UserResponse body = UserResponse.of(result.user());
        return result.created()
            ? ResponseEntity.created(URI.create("/api/v1/auth/users/" + body.userId())).body(body)
            : ResponseEntity.ok(body);
    }

    @GetMapping("/users/{id}")
    public UserResponse get(@AuthenticationPrincipal AuthenticatedCaller caller, @PathVariable("id") String id) {
        return UserResponse.of(getUser.execute(caller, id));
    }

    @PostMapping("/users/search")
    public SearchResponse search(@AuthenticationPrincipal AuthenticatedCaller caller,
                                 @RequestBody JsonNode body) {
        if (!body.isObject()) {
            throw invalidSearch("body", "The request body must be an object");
        }
        body.fieldNames().forEachRemaining(field -> {
            if (!List.of("q", "role", "page", "limit").contains(field)) {
                throw invalidSearch("body", "Unexpected search filter");
            }
        });
        SearchUsersResult result = searchUsers.execute(caller, new SearchUsersCommand(
            searchText(body, "q"), searchText(body, "role"),
            searchNumber(body, "page"), searchNumber(body, "limit")));
        return SearchResponse.of(result);
    }

    private static String searchText(JsonNode body, String field) {
        JsonNode value = body.get(field);
        if (value == null) return null;
        if (!value.isTextual()) throw invalidSearch(field, "The field must be text");
        return value.textValue();
    }

    private static Integer searchNumber(JsonNode body, String field) {
        JsonNode value = body.get(field);
        if (value == null) return null;
        if (!value.isIntegralNumber() || !value.canConvertToInt()) {
            throw invalidSearch(field, "The field must be an integer");
        }
        return value.intValue();
    }

    private static ValidationException invalidSearch(String field, String message) {
        return new ValidationException(List.of(new ValidationException.Problem(field, message)));
    }
}
