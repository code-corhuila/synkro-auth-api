package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenSigner;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore;
import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore.Issued;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.ServiceAccount;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class IssueServiceTokenUseCase {
    private final ServiceTokenStore tokens;
    private final ServiceTokenSigner signer;
    private final IdGenerator ids;
    private final Clock clock;

    public IssueServiceTokenUseCase(ServiceTokenStore tokens, ServiceTokenSigner signer, IdGenerator ids, Clock clock) {
        this.tokens = tokens;
        this.signer = signer;
        this.ids = ids;
        this.clock = clock;
    }

    public IssueServiceTokenResult execute(AuthenticatedCaller caller, IssueServiceTokenCommand command) {
        RoleGuard.requireAnyRole(caller, "issue service tokens", Roles.ADMIN);
        ServiceAccount account = IssueServiceTokenValidator.validate(command);

        Optional<ServiceToken> original = tokens.findByIdempotencyKey(command.idempotencyKey());
        if (original.isPresent()) {
            return replay(account, original.get());
        }

        // A JWT carries whole seconds and PostgreSQL microseconds: whole seconds make the claims, the
        // row and the response agree exactly.
        ServiceToken token = ServiceToken.issue(account, ids.newId(), caller.subject(),
            clock.instant().truncatedTo(ChronoUnit.SECONDS));
        // Signed before the transaction and kept in this frame: if the commit fails the exception
        // leaves the stack with it, and a request that lost the race simply drops its own copy.
        String signedToken = signer.sign(token);
        Issued saved = tokens.issueOnce(command.idempotencyKey(), token);
        return saved.created() ? IssueServiceTokenResult.created(saved.token(), signedToken) : replay(account, saved.token());
    }

    // A key is only an answer to the request that used it: anything else must not be shown that token.
    private IssueServiceTokenResult replay(ServiceAccount account, ServiceToken original) {
        if (!original.service().equals(account.serviceName())) {
            throw new BusinessRuleViolationException(IdempotencyKeyRule.FIELD,
                "The Idempotency-Key was already used with a different request");
        }
        return IssueServiceTokenResult.replayed(original);
    }
}
