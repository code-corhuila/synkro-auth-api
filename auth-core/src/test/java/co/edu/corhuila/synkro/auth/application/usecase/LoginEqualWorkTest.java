package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.ArrayList;
import java.util.List;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.HASH;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.REFRESH_TTL;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.user;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.users;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * A failed login must cost the same as any other: its response time must not tell a client whether an email
 * exists. Timing assertions are flaky, so this checks the work performed (how many password verifications ran
 * and against what), which is what the milliseconds measure.
 */
class LoginEqualWorkTest {

    /** Records every call, so the tests can compare the work of different logins. */
    private static final class SpyingHasher implements PasswordHasher {
        final List<String> hashed = new ArrayList<>();
        final List<String[]> verified = new ArrayList<>();

        @Override
        public String hash(String plaintext) {
            hashed.add(plaintext);
            return PASSWORD_HASHER.hash(plaintext);
        }

        @Override
        public boolean matches(String plaintext, String hash) {
            verified.add(new String[] {plaintext, hash});
            return PASSWORD_HASHER.matches(plaintext, hash);
        }
    }

    private SpyingHasher hasher;
    private LoginUseCase login;

    @BeforeEach
    void setUp() {
        hasher = new SpyingHasher();
        login = new LoginUseCase(
            users(user("ana@synkro.test", true), user("off@synkro.test", false)),
            hasher, new Fakes.RecordingTokenIssuer(), new Fakes.FakeRefreshTokenStore(), HASH, CLOCK, REFRESH_TTL);
        hasher.verified.clear();
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "wrong password,       ana@synkro.test,   not-the-password",
        "unknown email,        ghost@synkro.test, correct-password",
        "inactive user,        off@synkro.test,   correct-password",
        "inactive wrong pass,  off@synkro.test,   not-the-password"})
    void everyFailedLogin_verifiesAPasswordExactlyOnce_andRaisesTheSameError(String label, String email, String password) {
        Throwable thrown = catchThrowable(() -> login.execute(email, password));

        assertThat(thrown).isExactlyInstanceOf(InvalidCredentialsException.class).hasMessage("invalid credentials");
        assertThat(hasher.verified).as("password verifications for: " + label).hasSize(1);
        assertThat(hasher.verified.get(0)[0]).isEqualTo(password);
    }

    @Test
    void aSuccessfulLogin_verifiesExactlyOnceToo() {
        login.execute("ana@synkro.test", PASSWORD);

        assertThat(hasher.verified).hasSize(1);
    }

    @Test
    void aMissingPassword_isRefusedAfterTheSameVerification() {
        Throwable thrown = catchThrowable(() -> login.execute("ana@synkro.test", null));

        assertThat(thrown).isInstanceOf(InvalidCredentialsException.class);
        assertThat(hasher.verified).hasSize(1);
    }

    @Test
    void anUnknownEmail_isVerifiedAgainstAHashMadeByTheHasher_notAUsersHash() {
        catchThrowable(() -> login.execute("ghost@synkro.test", PASSWORD));

        String verifiedAgainst = hasher.verified.get(0)[1];
        assertThat(hasher.hashed).as("the stand-in hash comes from the hasher, so it has the same cost")
            .anyMatch(plaintext -> PASSWORD_HASHER.hash(plaintext).equals(verifiedAgainst));
        assertThat(verifiedAgainst).isNotEqualTo(user("ana@synkro.test", true).getPasswordHash());
        assertThat(PASSWORD_HASHER.matches(PASSWORD, verifiedAgainst)).as("the stand-in never accepts a real password").isFalse();
    }

    @Test
    void theStandInHashIsComputedOnceAtStartup_notOnEveryFailedLogin() {
        int hashedAtStartup = hasher.hashed.size();

        for (int i = 0; i < 5; i++) {
            catchThrowable(() -> login.execute("ghost@synkro.test", PASSWORD));
        }

        assertThat(hashedAtStartup).isEqualTo(1);
        assertThat(hasher.hashed).hasSize(hashedAtStartup);
    }

    @Test
    void anInactiveUserWithTheRightPassword_isStillRefused() {
        Throwable thrown = catchThrowable(() -> login.execute("off@synkro.test", PASSWORD));

        assertThat(thrown).isInstanceOf(InvalidCredentialsException.class);
    }
}
