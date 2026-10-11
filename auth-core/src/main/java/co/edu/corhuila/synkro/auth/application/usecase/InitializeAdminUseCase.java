package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore;
import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore.InitializationAudit;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.domain.model.Emails;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Creates the first ADMIN of an environment, attributed to the operator who ran the command (HU-AUTH-14).
 *
 * It has no caller: there is no ADMIN yet to authenticate as, and the authorization is the controlled deployment
 * session that runs it, not anything this class can check. It is not ordinary registration and shares none of its
 * authorization or idempotency. The input is validated before anything is hashed or generated, and the password
 * is hashed here, before the store opens its transaction, so the lock is never held while bcrypt runs.
 */
public class InitializeAdminUseCase {
    private final InitialAdminStore store;
    private final PasswordHasher hasher;
    private final IdGenerator ids;
    private final Clock clock;

    public InitializeAdminUseCase(InitialAdminStore store, PasswordHasher hasher, IdGenerator ids, Clock clock) {
        this.store = store;
        this.hasher = hasher;
        this.ids = ids;
        this.clock = clock;
    }

    public InitialAdminResult execute(InitialAdminCommand command) {
        InitializeAdminValidator.validate(command);
        // PostgreSQL keeps microseconds; truncating here makes what is written equal what a later read returns.
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);

        SystemUser admin = new SystemUser(ids.newId(), command.name(), Emails.normalize(command.email()),
            hasher.hash(command.password()), Roles.ADMIN, now, true);
        InitializationAudit audit = new InitializationAudit(ids.newId(), command.operatorIdentity().strip(), now,
            command.correlationId());
        return store.initializeAdministrator(admin, audit);
    }
}
