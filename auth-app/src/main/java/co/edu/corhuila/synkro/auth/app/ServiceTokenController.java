package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.application.usecase.GetServiceTokenUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.IssueServiceTokenCommand;
import co.edu.corhuila.synkro.auth.application.usecase.IssueServiceTokenResult;
import co.edu.corhuila.synkro.auth.application.usecase.IssueServiceTokenUseCase;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;
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
 * issueServiceToken and getServiceToken of synkro-auth-api.yaml. The controller only translates HTTP into
 * a command and a result back into HTTP: validation and the ADMIN decision belong to the use cases.
 * The request is read for the service alone; whatever else it carries is never looked at.
 */
@RestController
@RequestMapping("/api/v1/auth/service-tokens")
public class ServiceTokenController {

    public record IssueServiceTokenRequest(String service) {}

    /** Mirrors ServiceTokenResponse: the metadata of a token, never the token. */
    public record ServiceTokenResponse(String tokenId, String service, List<String> permissions, String issuedBy,
                                       Instant issuedAt, Instant expiresAt) {
        static ServiceTokenResponse of(ServiceToken token) {
            return new ServiceTokenResponse(token.tokenId(), token.service(), token.permissions(), token.issuedBy(),
                token.issuedAt(), token.expiresAt());
        }
    }

    /** Mirrors ServiceTokenIssuedResponse: the only body that carries the token. toString leaves it out. */
    public record ServiceTokenIssuedResponse(String tokenId, String service, List<String> permissions, String issuedBy,
                                             Instant issuedAt, Instant expiresAt, String token) {
        static ServiceTokenIssuedResponse of(ServiceToken metadata, String token) {
            return new ServiceTokenIssuedResponse(metadata.tokenId(), metadata.service(), metadata.permissions(),
                metadata.issuedBy(), metadata.issuedAt(), metadata.expiresAt(), token);
        }

        @Override
        public String toString() {
            return "ServiceTokenIssuedResponse[tokenId=" + tokenId + ", service=" + service + "]";
        }
    }

    private final IssueServiceTokenUseCase issueServiceToken;
    private final GetServiceTokenUseCase getServiceToken;

    public ServiceTokenController(IssueServiceTokenUseCase issueServiceToken, GetServiceTokenUseCase getServiceToken) {
        this.issueServiceToken = issueServiceToken;
        this.getServiceToken = getServiceToken;
    }

    @PostMapping
    public ResponseEntity<?> issue(@AuthenticationPrincipal AuthenticatedCaller caller,
                                   @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
                                   @RequestBody IssueServiceTokenRequest request) {
        IssueServiceTokenResult result = issueServiceToken.execute(caller,
            new IssueServiceTokenCommand(idempotencyKey, request.service()));
        if (!result.created()) {
            return ResponseEntity.ok(ServiceTokenResponse.of(result.token()));
        }
        return ResponseEntity.created(URI.create("/api/v1/auth/service-tokens/" + result.token().tokenId()))
            .body(ServiceTokenIssuedResponse.of(result.token(), result.signedToken()));
    }

    @GetMapping("/{id}")
    public ServiceTokenResponse get(@AuthenticationPrincipal AuthenticatedCaller caller, @PathVariable("id") String id) {
        return ServiceTokenResponse.of(getServiceToken.execute(caller, id));
    }
}
