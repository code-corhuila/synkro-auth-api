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
import java.util.Optional;

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

        // The key comes first: a retry must find its user even though its email is now taken.
        Optional<SystemUser> original = registrations.findByIdempotencyKey(command.idempotencyKey());
        if (original.isPresent()) {
            return replay(command, email, original.get());
        }
        if (users.findByEmail(email).isPresent()) {
            throw new BusinessRuleViolationException("email", "The email is already registered");
        }

        // PostgreSQL keeps microseconds; truncating here makes the response equal what a later read returns.
        SystemUser user = new SystemUser(ids.newId(), command.name(), email, hasher.hash(command.password()),
            command.role(), clock.instant().truncatedTo(ChronoUnit.MICROS), true);
        Registered saved = registrations.registerOnce(command.idempotencyKey(), user);
        return saved.created() ? new RegisterUserResult(saved.user(), true) : replay(command, email, saved.user());
    }

    // A key is only an answer to the request that created it: anything else must not be shown that user.
    private RegisterUserResult replay(RegisterUserCommand command, String email, SystemUser original) {
        boolean sameRequest = original.getName().equals(command.name())
            && original.getEmail().equals(email)
            && original.getRole().equals(command.role())
            && hasher.matches(command.password(), original.getPasswordHash());
        if (!sameRequest) {
            throw new BusinessRuleViolationException(RegisterUserValidator.IDEMPOTENCY_KEY,
                "The Idempotency-Key was already used with a different request");
        }
        return new RegisterUserResult(original, false);
    }
}
