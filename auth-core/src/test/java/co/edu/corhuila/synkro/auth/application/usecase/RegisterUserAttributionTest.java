package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore.CreationAttribution;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.NOW;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;

/** What the use case hands the store to record: the creator comes from the verified caller, never from the body. */
class RegisterUserAttributionTest {

    private FakeUserRegistrationStore store;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new FakeUserRegistrationStore();
        AtomicInteger sequence = new AtomicInteger();
        register = new RegisterUserUseCase(store, store, PASSWORD_HASHER, () -> "id-" + sequence.incrementAndGet(), CLOCK);
    }

    private static RegisterUserCommand command() {
        return new RegisterUserCommand("key-0001-abcd", "Ana Perez", "ana@synkro.test", "a-long-password", "SALESPERSON");
    }

    @Test
    void aCreatedUserIsAttributedToTheVerifiedCaller_withTheRequestsCorrelationIdAndTheCurrentTime() {
        RegisterUserResult result = register.execute(ADMIN_CALLER, CORRELATION_ID, command());

        CreationAttribution attribution = store.attributions.get(result.user().getUserId());
        assertThat(attribution.actorUserId()).isEqualTo(ADMIN_CALLER.subject());
        assertThat(attribution.correlationId()).isEqualTo(CORRELATION_ID);
        assertThat(attribution.occurredAt()).isEqualTo(NOW);
        assertThat(attribution.auditId()).isNotBlank().isNotEqualTo(result.user().getUserId());
    }

    @Test
    void aReplayRecordsNoSecondAttribution() {
        register.execute(ADMIN_CALLER, CORRELATION_ID, command());

        register.execute(ADMIN_CALLER, "corr-0002", command());

        assertThat(store.attributions).hasSize(1);
        assertThat(store.attributions.values()).extracting(CreationAttribution::correlationId).containsExactly(CORRELATION_ID);
    }
}
