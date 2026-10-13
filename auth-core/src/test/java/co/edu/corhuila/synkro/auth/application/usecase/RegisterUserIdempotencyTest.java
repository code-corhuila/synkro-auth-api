package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The same Idempotency-Key never creates a second user, and never reveals one to a request that does not match. */
class RegisterUserIdempotencyTest {

    private static final String KEY = "key-0001-abcd";

    private FakeUserRegistrationStore store;
    private AtomicInteger hashCalls;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new FakeUserRegistrationStore();
        hashCalls = new AtomicInteger();
        PasswordHasher counting = new PasswordHasher() {
            @Override
            public String hash(String plaintext) {
                hashCalls.incrementAndGet();
                return PASSWORD_HASHER.hash(plaintext);
            }

            @Override
            public boolean matches(String plaintext, String hash) {
                return PASSWORD_HASHER.matches(plaintext, hash);
            }
        };
        AtomicInteger sequence = new AtomicInteger();
        IdGenerator ids = () -> "user-" + sequence.incrementAndGet();
        register = new RegisterUserUseCase(store, store, counting, ids, CLOCK);
    }

    private static RegisterUserCommand command(String key, String name, String email, String password, String role) {
        return new RegisterUserCommand(key, name, email, password, role);
    }

    private static RegisterUserCommand original() {
        return command(KEY, "Ana Perez", "ana@synkro.test", "a-long-password", "SALESPERSON");
    }

    @Test
    void theSameKeyAndRequest_returnsTheSameUser_andSavesNothingNew() {
        RegisterUserResult first = register.execute(original());

        RegisterUserResult second = register.execute(original());

        assertThat(first.created()).isTrue();
        assertThat(second.created()).isFalse();
        assertThat(second.user().getUserId()).isEqualTo(first.user().getUserId());
        assertThat(store.byKey).hasSize(1);
        assertThat(store.byEmail).hasSize(1);
        assertThat(store.registerCalls).isEqualTo(1);
    }

    @Test
    void aReplayDoesNotHashThePasswordAgain() {
        register.execute(original());
        register.execute(original());

        assertThat(hashCalls).hasValue(1);
    }

    @Test
    void aReplayThatSpellsTheEmailDifferently_isStillTheSameRequest() {
        RegisterUserResult first = register.execute(original());

        RegisterUserResult second = register.execute(
            command(KEY, "Ana Perez", "  ANA@synkro.TEST", "a-long-password", "SALESPERSON"));

        assertThat(second.created()).isFalse();
        assertThat(second.user().getUserId()).isEqualTo(first.user().getUserId());
    }

    @Test
    void theSameKeyWithADifferentBody_isRefused_andShowsNothingOfTheFirstUser() {
        register.execute(original());

        for (RegisterUserCommand other : new RegisterUserCommand[] {
            command(KEY, "Someone Else", "ana@synkro.test", "a-long-password", "SALESPERSON"),
            command(KEY, "Ana Perez", "other@synkro.test", "a-long-password", "SALESPERSON"),
            command(KEY, "Ana Perez", "ana@synkro.test", "another-password", "SALESPERSON"),
            command(KEY, "Ana Perez", "ana@synkro.test", "a-long-password", "ADMIN")}) {
            assertThatThrownBy(() -> register.execute(other))
                .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> {
                    assertThat(e.field()).isEqualTo("Idempotency-Key");
                    assertThat(e.getMessage()).doesNotContain("ana@synkro.test", "Ana Perez", "user-1");
                });
        }
        assertThat(store.byKey).hasSize(1);
    }

    @Test
    void whenAnotherRequestWinsTheRace_theLoserGetsTheWinnersUser_withoutCreatingAnything() {
        SystemUser winner = new SystemUser("winner-id", "Ana Perez", "ana@synkro.test",
            PASSWORD_HASHER.hash("a-long-password"), "SALESPERSON", Fakes.NOW, true);
        UserRegistrationStore racing = new UserRegistrationStore() {
            @Override
            public Optional<SystemUser> findByIdempotencyKey(String idempotencyKey) {
                return Optional.empty();
            }

            @Override
            public Registered registerOnce(String idempotencyKey, SystemUser user) {
                return new Registered(winner, false);
            }
        };
        RegisterUserUseCase loser = new RegisterUserUseCase(store, racing, PASSWORD_HASHER, () -> "loser-id", CLOCK);

        RegisterUserResult result = loser.execute(original());

        assertThat(result.created()).isFalse();
        assertThat(result.user().getUserId()).isEqualTo("winner-id");
    }

    @Test
    void whenAnotherRequestWinsTheRaceWithADifferentBody_theLoserIsRefused() {
        SystemUser winner = new SystemUser("winner-id", "Someone Else", "else@synkro.test",
            PASSWORD_HASHER.hash("a-long-password"), "ADMIN", Fakes.NOW, true);
        UserRegistrationStore racing = new UserRegistrationStore() {
            @Override
            public Optional<SystemUser> findByIdempotencyKey(String idempotencyKey) {
                return Optional.empty();
            }

            @Override
            public Registered registerOnce(String idempotencyKey, SystemUser user) {
                return new Registered(winner, false);
            }
        };
        RegisterUserUseCase loser = new RegisterUserUseCase(store, racing, PASSWORD_HASHER, () -> "loser-id", CLOCK);

        assertThatThrownBy(() -> loser.execute(original())).isInstanceOf(BusinessRuleViolationException.class);
    }
}
