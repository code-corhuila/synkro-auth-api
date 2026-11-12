package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.SALES_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.KEY;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.NEW_PASSWORD;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The request breaks the contract before any key, target or storage is involved: nothing is read or written. */
class ResetUserPasswordValidationTest {

    private FakePasswordResetStore store;
    private ResetUserPasswordUseCase reset;

    @BeforeEach
    void setUp() {
        store = new FakePasswordResetStore();
        reset = new ResetUserPasswordUseCase(store, store, PASSWORD_HASHER, () -> "audit-1", CLOCK, Fakes.IGNORED_RESET_ATTEMPTS);
    }

    private List<Problem> problemsOf(ResetUserPasswordCommand command) {
        var thrown = org.assertj.core.api.Assertions.catchThrowableOfType(ValidationException.class,
            () -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command));
        assertThat(thrown).as("a ValidationException").isNotNull();
        assertThat(store.lookups).as("no key lookup").isZero();
        assertThat(store.resetCalls).as("no reset attempted").isZero();
        assertThat(store.audits).isEmpty();
        return thrown.problems();
    }

    private static ResetUserPasswordCommand with(String id, String key, String password, String confirm) {
        return new ResetUserPasswordCommand(id, key, password, confirm);
    }

    @Test
    void aMalformedTargetId_isRejectedOnTheId() {
        for (String id : new String[] {null, "", "not-a-uuid", "1-1-1-1-1", SALES_ID + "0", " " + SALES_ID, "../" + SALES_ID}) {
            assertThat(problemsOf(with(id, KEY, NEW_PASSWORD, NEW_PASSWORD))).extracting(Problem::field).containsExactly("id");
        }
    }

    @Test
    void aMissingOrOutOfRangeIdempotencyKey_isRejectedOnTheKey() {
        for (String key : new String[] {null, "", "short", "x".repeat(129)}) {
            assertThat(problemsOf(with(SALES_ID, key, NEW_PASSWORD, NEW_PASSWORD))).extracting(Problem::field)
                .containsExactly("Idempotency-Key");
        }
    }

    @Test
    void aKeyAtTheLimits_isAccepted() {
        for (String key : new String[] {"x".repeat(8), "x".repeat(128)}) {
            ResetUserPasswordResult result = reset.execute(ADMIN_CALLER, CORRELATION_ID, with(SALES_ID, key, NEW_PASSWORD, NEW_PASSWORD));
            assertThat(result.userId()).isEqualTo(SALES_ID);
        }
    }

    @Test
    void aMissingOrTooShortPassword_isRejectedOnNewPassword() {
        for (String password : new String[] {null, "", "1234567"}) {
            assertThat(problemsOf(with(SALES_ID, KEY, password, password))).extracting(Problem::field).containsExactly("newPassword");
        }
    }

    @Test
    void aPasswordOfMoreThan72Bytes_isRejected_countingBytesNotCharacters() {
        String seventyThreeBytes = "x".repeat(73);
        String manyAccents = "é".repeat(37); // 74 bytes in UTF-8, only 37 characters

        for (String password : new String[] {seventyThreeBytes, manyAccents}) {
            assertThat(problemsOf(with(SALES_ID, KEY, password, password))).extracting(Problem::field).containsExactly("newPassword");
        }
    }

    @Test
    void aPasswordOfExactly72BytesOrEightCharacters_isAccepted() {
        for (String password : new String[] {"x".repeat(72), "12345678", "é".repeat(36)}) {
            ResetUserPasswordResult result = reset.execute(ADMIN_CALLER, CORRELATION_ID, with(SALES_ID, KEY + password.length(), password, password));
            assertThat(result.userId()).isEqualTo(SALES_ID);
        }
    }

    @Test
    void aConfirmationThatDiffers_isRejectedOnConfirmPassword() {
        for (String confirm : new String[] {null, "", NEW_PASSWORD + "x", NEW_PASSWORD.toUpperCase()}) {
            assertThat(problemsOf(with(SALES_ID, KEY, NEW_PASSWORD, confirm))).extracting(Problem::field)
                .containsExactly("confirmPassword");
        }
    }

    @Test
    void severalProblemsAreReportedTogether_oneEntryPerField() {
        List<Problem> problems = problemsOf(with("nope", "x", "short", "other"));

        assertThat(problems).extracting(Problem::field).containsExactlyInAnyOrder("id", "Idempotency-Key", "newPassword", "confirmPassword");
    }

    @Test
    void noValidationMessageRepeatsAValueTheCallerSent() {
        String secret = "tiny";
        String key = "k-secret";

        List<Problem> problems = problemsOf(with("id-secret", key, secret, "other-secret"));

        assertThat(problems).extracting(Problem::message)
            .noneMatch(m -> m.contains(secret) || m.contains(key) || m.contains("id-secret") || m.contains("other-secret"));
    }

    @Test
    void aShortPasswordIsReportedBeforeAnythingAboutTheTarget_soAnUnknownTargetNeverGetsThatFar() {
        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID,
            with(FakePasswordResetStore.MISSING_ID, KEY, "short", "short"))).isInstanceOf(ValidationException.class);
    }
}
