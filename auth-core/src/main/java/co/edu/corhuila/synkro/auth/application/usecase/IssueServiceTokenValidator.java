package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import co.edu.corhuila.synkro.auth.domain.model.ServiceAccount;

import java.util.ArrayList;
import java.util.List;

/** The limits of IssueServiceTokenRequest in synkro-auth-api.yaml, in one place. */
final class IssueServiceTokenValidator {
    private static final String SERVICE = "service";

    private IssueServiceTokenValidator() {}

    static ServiceAccount validate(IssueServiceTokenCommand command) {
        List<Problem> problems = new ArrayList<>();
        IdempotencyKeyRule.check(problems, command.idempotencyKey());
        ServiceAccount account = checkService(problems, command.service());
        if (!problems.isEmpty()) {
            throw new ValidationException(problems);
        }
        return account;
    }

    private static ServiceAccount checkService(List<Problem> problems, String service) {
        if (service == null || service.isBlank()) {
            problems.add(new Problem(SERVICE, "The field service is required"));
            return null;
        }
        return ServiceAccount.fromName(service).orElseGet(() -> {
            problems.add(new Problem(SERVICE, "The field service must be synkro-workflow or synkro-worker"));
            return null;
        });
    }
}
