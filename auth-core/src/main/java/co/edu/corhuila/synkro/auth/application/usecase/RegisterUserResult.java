package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

/** {@code created} is false when the idempotency key had already created this user. */
public record RegisterUserResult(SystemUser user, boolean created) {
}
