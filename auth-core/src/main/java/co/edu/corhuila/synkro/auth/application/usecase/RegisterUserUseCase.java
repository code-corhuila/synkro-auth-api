package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore.Registered;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.Emails;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.temporal.ChronoUnit;

public class RegisterUserUseCase {
    private final UserRepository users;
    private final UserRegistrationStore registrations;
    private final PasswordHasher hasher;
    private final IdGenerator ids;
    private final Clock clock;

    public RegisterUserUseCase(UserRepository users, UserRegistrationStore registrations, PasswordHasher hasher,
                               IdGenerator ids, Clock clock) {
        this.users = users;
        this.registrations = registrations;
        this.hasher = hasher;
        this.ids = ids;
        this.clock = clock;
    }

    public RegisterUserResult execute(RegisterUserCommand command) {
        RegisterUserValidator.validate(command);
        String email = Emails.normalize(command.email());
        if (users.findByEmail(email).isPresent()) {
            throw emailTaken();
        }

        // PostgreSQL keeps microseconds; truncating here makes the response equal what a later read returns.
        SystemUser user = new SystemUser(ids.newId(), command.name(), email, hasher.hash(command.password()),
            command.role(), clock.instant().truncatedTo(ChronoUnit.MICROS), true);
        Registered saved = registrations.registerOnce(command.idempotencyKey(), user);
        return new RegisterUserResult(saved.user(), saved.created());
    }

    private static BusinessRuleViolationException emailTaken() {
        return new BusinessRuleViolationException("email", "The email is already registered");
    }
}
