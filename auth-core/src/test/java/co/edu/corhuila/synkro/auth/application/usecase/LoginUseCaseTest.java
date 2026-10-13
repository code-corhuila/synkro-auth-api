package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.Fakes.FakeRefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.usecase.Fakes.RecordingTokenIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.HASH;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.user;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.users;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

class LoginUseCaseTest {

    private RecordingTokenIssuer issuer;
    private FakeRefreshTokenStore store;
    private LoginUseCase login;

    @BeforeEach
    void setUp() {
        issuer = new RecordingTokenIssuer();
        store = new FakeRefreshTokenStore();
        login = new LoginUseCase(
            users(user("ana@synkro.test", true), user("off@synkro.test", false)),
            PASSWORD_HASHER, issuer, store, HASH);
    }

    @Test
    void validCredentials_returnBothTokens() {
        LoginResult result = login.execute("ana@synkro.test", PASSWORD);

        assertThat(result.accessToken()).startsWith("access-u-1-ADMIN");
        assertThat(result.refreshToken()).isEqualTo("refresh-1");
    }

    @Test
    void successfulLogin_storesTheRefreshTokenHash_neverTheRawValue() {
        LoginResult result = login.execute("ana@synkro.test", PASSWORD);

        assertThat(store.hashToUser).containsOnlyKeys(HASH.hash(result.refreshToken()));
        assertThat(store.hashToUser).doesNotContainKey(result.refreshToken());
        assertThat(store.hashToUser.get(HASH.hash(result.refreshToken()))).isEqualTo("u-1");
    }

    @Test
    void wrongPassword_isRejected_andIssuesNothing() {
        assertThatThrownBy(() -> login.execute("ana@synkro.test", "nope"))
            .isInstanceOf(InvalidCredentialsException.class);
        assertThat(issuer.accessSubjects).isEmpty();
        assertThat(store.hashToUser).isEmpty();
    }

    @Test
    void unknownEmail_isRejected() {
        assertThatThrownBy(() -> login.execute("ghost@synkro.test", PASSWORD))
            .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void inactiveUser_isRejected_evenWithTheRightPassword() {
        assertThatThrownBy(() -> login.execute("off@synkro.test", PASSWORD))
            .isInstanceOf(InvalidCredentialsException.class);
        assertThat(issuer.accessSubjects).isEmpty();
    }

    @Test
    void allFailureModes_throwTheSameError_soLoginCannotBeEnumerated() {
        Throwable wrongPassword = catchThrowable(() -> login.execute("ana@synkro.test", "nope"));
        Throwable unknownEmail = catchThrowable(() -> login.execute("ghost@synkro.test", PASSWORD));
        Throwable inactive = catchThrowable(() -> login.execute("off@synkro.test", PASSWORD));

        assertThat(unknownEmail).isExactlyInstanceOf(wrongPassword.getClass()).hasMessage(wrongPassword.getMessage());
        assertThat(inactive).isExactlyInstanceOf(wrongPassword.getClass()).hasMessage(wrongPassword.getMessage());
    }
}
