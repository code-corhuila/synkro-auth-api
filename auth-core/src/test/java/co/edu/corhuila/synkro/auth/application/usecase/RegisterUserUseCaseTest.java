package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.concurrent.atomic.AtomicInteger;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.NOW;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

class RegisterUserUseCaseTest {

    private static final String KEY = "key-0001-abcd";

    private FakeUserRegistrationStore store;
    private RegisterUserUseCase register;

    @BeforeEach
    void setUp() {
        store = new FakeUserRegistrationStore();
        AtomicInteger sequence = new AtomicInteger();
        IdGenerator ids = () -> "user-" + sequence.incrementAndGet();
        register = new RegisterUserUseCase(store, store, PASSWORD_HASHER, ids, CLOCK);
    }

    private static RegisterUserCommand command(String key, String name, String email, String password, String role) {
        return new RegisterUserCommand(key, name, email, password, role);
    }

    private static RegisterUserCommand valid() {
        return command(KEY, "Ana Perez", "ana@synkro.test", "a-long-password", "SALESPERSON");
    }

    private Problem problemOf(RegisterUserCommand command) {
        Throwable thrown = catchThrowable(() -> register.execute(command));
        assertThat(thrown).isInstanceOf(ValidationException.class);
        return ((ValidationException) thrown).problems().get(0);
    }

    @Test
    void registeringANewEmail_returnsTheCreatedUserWithItsRole() {
        RegisterUserResult result = register.execute(valid());

        assertThat(result.created()).isTrue();
        assertThat(result.user().getUserId()).isEqualTo("user-1");
        assertThat(result.user().getName()).isEqualTo("Ana Perez");
        assertThat(result.user().getEmail()).isEqualTo("ana@synkro.test");
        assertThat(result.user().getRole()).isEqualTo("SALESPERSON");
        assertThat(result.user().isActive()).isTrue();
        assertThat(result.user().getRegistrationDate()).isEqualTo(NOW);
    }

    @Test
    void theStoredHashIsNotThePassword_andItVerifies() {
        register.execute(valid());

        String stored = store.byEmail.get("ana@synkro.test").getPasswordHash();
        assertThat(stored).isNotEqualTo("a-long-password");
        assertThat(PASSWORD_HASHER.matches("a-long-password", stored)).isTrue();
    }

    @Test
    void theIdempotencyRecordIsSavedWithTheUser() {
        RegisterUserResult result = register.execute(valid());

        assertThat(store.byKey).containsOnlyKeys(KEY);
        assertThat(store.byKey.get(KEY).getUserId()).isEqualTo(result.user().getUserId());
    }

    @Test
    void anExistingEmailWithANewKey_isABusinessRuleViolationNamingEmail() {
        register.execute(valid());

        assertThatThrownBy(() -> register.execute(command("key-0002-abcd", "Other", "ana@synkro.test", "another-password", "ADMIN")))
            .isInstanceOfSatisfying(BusinessRuleViolationException.class, e -> assertThat(e.field()).isEqualTo("email"));
        assertThat(store.byKey).containsOnlyKeys(KEY);
    }

    @Test
    void aSpellingOfAnExistingEmailThatOnlyDiffersInCaseOrSpaces_isTheSameEmail() {
        register.execute(valid());

        assertThatThrownBy(() -> register.execute(command("key-0002-abcd", "Other", "  ANA@Synkro.Test ", "another-password", "ADMIN")))
            .isInstanceOf(BusinessRuleViolationException.class);
    }

    @Test
    void theEmailIsStoredTrimmedAndLowercase() {
        RegisterUserResult result = register.execute(command(KEY, "Ana", "  Ana.Perez@Synkro.TEST ", "a-long-password", "ADMIN"));

        assertThat(result.user().getEmail()).isEqualTo("ana.perez@synkro.test");
    }

    @ParameterizedTest
    @ValueSource(strings = {"SERVICE", "OWNER", "admin", "", " "})
    void aRoleThatIsNotAPersonRole_isRejectedBeforeTouchingStorage(String role) {
        Problem problem = problemOf(command(KEY, "Ana", "ana@synkro.test", "a-long-password", role));

        assertThat(problem.field()).isEqualTo("role");
        assertThat(store.registerCalls).isZero();
        assertThat(store.byKey).isEmpty();
    }

    @Test
    void aMissingRole_isRejected() {
        assertThat(problemOf(command(KEY, "Ana", "ana@synkro.test", "a-long-password", null)).field()).isEqualTo("role");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "a@b", "no-at-sign.test", "two@@synkro.test", "spaces in@synkro.test"})
    void aMalformedOrTooShortEmail_isRejected(String email) {
        assertThat(problemOf(command(KEY, "Ana", email, "a-long-password", "ADMIN")).field()).isEqualTo("email");
    }

    @Test
    void anEmailOf256Characters_isRejected_andOf255IsAccepted() {
        String local = "a".repeat(255 - "@synkro.test".length());
        assertThat(register.execute(command(KEY, "Ana", local + "@synkro.test", "a-long-password", "ADMIN")).created()).isTrue();

        assertThat(problemOf(command("key-0002-abcd", "Ana", "a" + local + "@synkro.test", "a-long-password", "ADMIN")).field())
            .isEqualTo("email");
    }

    @Test
    void aMissingEmail_isRejected() {
        assertThat(problemOf(command(KEY, "Ana", null, "a-long-password", "ADMIN")).field()).isEqualTo("email");
    }

    @Test
    void aNameOf151Characters_isRejected_andOf150IsAccepted() {
        assertThat(register.execute(command(KEY, "n".repeat(150), "ana@synkro.test", "a-long-password", "ADMIN")).created()).isTrue();

        assertThat(problemOf(command("key-0002-abcd", "n".repeat(151), "b@synkro.test", "a-long-password", "ADMIN")).field())
            .isEqualTo("name");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void anEmptyOrBlankName_isRejected(String name) {
        assertThat(problemOf(command(KEY, name, "ana@synkro.test", "a-long-password", "ADMIN")).field()).isEqualTo("name");
    }

    @Test
    void aPasswordOf7Characters_isRejected_andOf8IsAccepted() {
        assertThat(problemOf(command(KEY, "Ana", "ana@synkro.test", "1234567", "ADMIN")).field()).isEqualTo("password");

        assertThat(register.execute(command(KEY, "Ana", "ana@synkro.test", "12345678", "ADMIN")).created()).isTrue();
    }

    @Test
    void aPasswordLongerThanBcryptCanUse_isRejected_insteadOfBeingSilentlyTruncated() {
        assertThat(problemOf(command(KEY, "Ana", "ana@synkro.test", "p".repeat(73), "ADMIN")).field()).isEqualTo("password");
        assertThat(register.execute(command(KEY, "Ana", "ana@synkro.test", "p".repeat(72), "ADMIN")).created()).isTrue();
    }

    @Test
    void aMissingPassword_isRejected() {
        assertThat(problemOf(command(KEY, "Ana", "ana@synkro.test", null, "ADMIN")).field()).isEqualTo("password");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 7, 129})
    void anIdempotencyKeyOutsideEightTo128Characters_isRejected(int length) {
        assertThat(problemOf(command("k".repeat(length), "Ana", "ana@synkro.test", "a-long-password", "ADMIN")).field())
            .isEqualTo("Idempotency-Key");
    }

    @Test
    void aMissingIdempotencyKey_isRejected() {
        assertThat(problemOf(command(null, "Ana", "ana@synkro.test", "a-long-password", "ADMIN")).field()).isEqualTo("Idempotency-Key");
    }

    @Test
    void keysOfExactlyEightAnd128Characters_areAccepted() {
        assertThat(register.execute(command("k".repeat(8), "Ana", "ana@synkro.test", "a-long-password", "ADMIN")).created()).isTrue();
        assertThat(register.execute(command("k".repeat(128), "Bo", "bo@synkro.test", "a-long-password", "ADMIN")).created()).isTrue();
    }

    @Test
    void everyInvalidFieldIsReportedAtOnce() {
        Throwable thrown = catchThrowable(() -> register.execute(command("short", "", "nope", "short", "SERVICE")));

        assertThat(((ValidationException) thrown).problems()).extracting(Problem::field)
            .containsExactlyInAnyOrder("Idempotency-Key", "name", "email", "password", "role");
    }
}
