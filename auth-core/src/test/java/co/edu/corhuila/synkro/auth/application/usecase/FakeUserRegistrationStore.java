package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Honours the contract of the port in memory: one user per key, one user per email. It doubles as the
 * UserRepository so a test sees what registration saved.
 */
class FakeUserRegistrationStore implements UserRegistrationStore, UserRepository {

    final Map<String, SystemUser> byKey = new LinkedHashMap<>();
    final Map<String, SystemUser> byEmail = new LinkedHashMap<>();
    /** What was recorded for each created user, by user id. */
    final Map<String, CreationAttribution> attributions = new LinkedHashMap<>();
    int registerCalls;

    /** Users that exist without having been registered here: the fixture administrator is one of them. */
    final Map<String, SystemUser> actors = new LinkedHashMap<>();

    FakeUserRegistrationStore() {
        actors.put(Fakes.ADMIN_CALLER.subject(),
            new SystemUser(Fakes.ADMIN_CALLER.subject(), "Fixture Admin", "fixture-admin@synkro.test", "hashed:x", "ADMIN", Fakes.NOW, true));
    }

    @Override
    public Optional<SystemUser> findByIdempotencyKey(String idempotencyKey) {
        return Optional.ofNullable(byKey.get(idempotencyKey));
    }

    @Override
    public Registered registerUserWithAttribution(String idempotencyKey, SystemUser user, CreationAttribution attribution) {
        registerCalls++;
        SystemUser original = byKey.get(idempotencyKey);
        if (original != null) {
            return new Registered(original, false);
        }
        if (byEmail.containsKey(user.getEmail())) {
            throw new BusinessRuleViolationException("email", "The email is already registered");
        }
        byKey.put(idempotencyKey, user);
        byEmail.put(user.getEmail(), user);
        attributions.put(user.getUserId(), attribution);
        return new Registered(user, true);
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return Optional.ofNullable(byEmail.get(email));
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        Optional<SystemUser> registered = byEmail.values().stream().filter(u -> u.getUserId().equals(userId)).findFirst();
        return registered.isPresent() ? registered : Optional.ofNullable(actors.get(userId));
    }
}
