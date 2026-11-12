package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Outcome;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.Recorded;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordResetStore.RequestReceipt;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.NOW;
import static org.assertj.core.api.Assertions.assertThat;

/** The receipt holds the bcrypt string of the original request: it must never leak through a string conversion. */
class RequestReceiptSecrecyTest {

    private static final String HASH = "$2a$12$" + "A".repeat(53);

    @Test
    void theReceiptNeverPrintsItsHash() {
        assertThat(new RequestReceipt(HASH).toString()).doesNotContain(HASH).doesNotContain("$2a$").contains("redacted");
    }

    @Test
    void aRecordThatHoldsTheReceiptNeverPrintsItsHashEither() {
        Recorded recorded = new Recorded("11111111-1111-1111-1111-111111111111", NOW, Optional.of(new RequestReceipt(HASH)));

        assertThat(recorded.toString()).doesNotContain(HASH).doesNotContain("$2a$");
        assertThat(new Outcome.AlreadyRecorded(recorded).toString()).doesNotContain(HASH).doesNotContain("$2a$");
    }

    @Test
    void theResultOfAReplayHoldsNoReceipt() {
        // ResetUserPasswordResult has no hash field at all: this documents that the answer is only id, instant and flag.
        assertThat(ResetUserPasswordResult.class.getRecordComponents()).extracting(c -> c.getName())
            .containsExactly("userId", "passwordResetAt", "replayed");
    }
}
