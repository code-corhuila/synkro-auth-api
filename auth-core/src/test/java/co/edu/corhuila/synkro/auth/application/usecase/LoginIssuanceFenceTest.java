package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.SALES_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.HASH;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.NOW;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.REFRESH_TTL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

/**
 * Login issuance fencing (HU-AUTH-19, ADR-021 Decision 3). The password is verified outside any transaction; the
 * credential is then persisted only if the user still stores exactly the hash that was verified. A reset that commits
 * in between makes the login fail with the generic 401: no refresh credential saved, no token returned.
 *
 * <p>The moment between verification and persistence is reached deterministically: the hasher double runs a hook right
 * after it verifies, which is where a concurrent reset would land. No test here sleeps.
 */
class LoginIssuanceFenceTest {

    private static final String EMAIL = "1111@synkro.test"; // the SALESPERSON of FakePasswordResetStore

    private FakePasswordResetStore users;
    private Fakes.FakeRefreshTokenStore refreshTokens;
    private Fakes.FakeCredentialIssuanceStore issuance;
    private Consumer<Void> afterVerification;
    private boolean verifiedInsideTheFence;
    private int verifications;
    private List<String> events;
    private LoginUseCase login;

    @BeforeEach
    void setUp() {
        users = new FakePasswordResetStore();
        refreshTokens = new Fakes.FakeRefreshTokenStore();
        issuance = Fakes.issuance(users, refreshTokens);
        afterVerification = ignored -> {};
        verifiedInsideTheFence = false;
        verifications = 0;
        events = new ArrayList<>();
        PasswordHasher slowVerifier = new PasswordHasher() {
            @Override
            public String hash(String plaintext) {
                return PASSWORD_HASHER.hash(plaintext);
            }

            @Override
            public boolean matches(String plaintext, String hash) {
                verifications++;
                verifiedInsideTheFence |= issuance.open;
                boolean matches = PASSWORD_HASHER.matches(plaintext, hash);
                afterVerification.accept(null);
                return matches;
            }
        };
        TokenIssuer issuer = new TokenIssuer() {
            @Override
            public String issueAccessToken(String subject, String role) {
                events.add("access:" + role + ":stored=" + refreshTokens.hashToUser.size());
                return "access-" + subject + "-" + role;
            }

            @Override
            public String issueRefreshToken() {
                events.add("refresh");
                return "refresh-1";
            }
        };
        login = new LoginUseCase(users, slowVerifier, issuer, issuance, HASH, CLOCK, REFRESH_TTL);
    }

    private void changeStoredHash(String newPassword) {
        SystemUser current = users.findById(SALES_ID).orElseThrow();
        users.replace(new SystemUser(current.getUserId(), current.getName(), current.getEmail(),
            PASSWORD_HASHER.hash(newPassword), current.getRole(), current.getRegistrationDate(), current.isActive()));
    }

    @Test
    void whenNothingChangedBetweenVerificationAndPersistence_theCredentialIsSavedAndReturned() {
        LoginResult result = login.execute(EMAIL, PASSWORD);

        assertThat(result.refreshToken()).isEqualTo("refresh-1");
        assertThat(refreshTokens.hashToUser).containsOnlyKeys(HASH.hash("refresh-1"));
        assertThat(refreshTokens.hashToUser.get(HASH.hash("refresh-1"))).isEqualTo(SALES_ID);
        assertThat(issuance.lastVerifiedHash).as("the port receives the exact hash that was verified")
            .isEqualTo(PASSWORD_HASHER.hash(PASSWORD));
    }

    @Test
    void aResetThatCommitsAfterTheVerificationButBeforeThePersistence_failsTheLoginWithTheGeneric401() {
        afterVerification = ignored -> changeStoredHash("the-passphrase-set-by-the-reset");

        Throwable thrown = catchThrowable(() -> login.execute(EMAIL, PASSWORD));

        assertThat(thrown).isExactlyInstanceOf(InvalidCredentialsException.class).hasMessage("invalid credentials");
        assertThat(refreshTokens.hashToUser).as("no refresh credential is saved").isEmpty();
        assertThat(events).as("no access token is issued").noneMatch(e -> e.startsWith("access"));
    }

    @Test
    void theFailureIsTheSameErrorAsAWrongPassword_soItRevealsNothing() {
        afterVerification = ignored -> changeStoredHash("the-passphrase-set-by-the-reset");
        Throwable fenced = catchThrowable(() -> login.execute(EMAIL, PASSWORD));
        afterVerification = ignored -> {};
        Throwable wrongPassword = catchThrowable(() -> login.execute(EMAIL, "not-the-password"));

        assertThat(fenced).isExactlyInstanceOf(wrongPassword.getClass()).hasMessage(wrongPassword.getMessage());
    }

    @Test
    void afterTheResetCommitted_aLoginWithTheNewPasswordWorks_andTheOldOneDoesNot() {
        changeStoredHash("the-passphrase-set-by-the-reset");

        assertThat(login.execute(EMAIL, "the-passphrase-set-by-the-reset").refreshToken()).isEqualTo("refresh-1");
        assertThat(catchThrowable(() -> login.execute(EMAIL, PASSWORD))).isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void aUserDeactivatedAfterTheVerification_isRefused_andNothingIsSaved() {
        afterVerification = ignored -> {
            SystemUser current = users.findById(SALES_ID).orElseThrow();
            users.replace(new SystemUser(current.getUserId(), current.getName(), current.getEmail(),
                current.getPasswordHash(), current.getRole(), current.getRegistrationDate(), false));
        };

        assertThat(catchThrowable(() -> login.execute(EMAIL, PASSWORD))).isInstanceOf(InvalidCredentialsException.class);
        assertThat(refreshTokens.hashToUser).isEmpty();
    }

    @Test
    void aUserRemovedAfterTheVerification_isRefused_andNothingIsSaved() {
        afterVerification = ignored -> users.users.remove(SALES_ID);

        assertThat(catchThrowable(() -> login.execute(EMAIL, PASSWORD))).isInstanceOf(InvalidCredentialsException.class);
        assertThat(refreshTokens.hashToUser).isEmpty();
    }

    @Test
    void theAccessTokenCarriesTheRoleOfTheIdentityReadInsideTheFence_notTheOneReadBeforeTheVerification() {
        afterVerification = ignored -> {
            SystemUser current = users.findById(SALES_ID).orElseThrow();
            users.replace(new SystemUser(current.getUserId(), current.getName(), current.getEmail(),
                current.getPasswordHash(), "INVENTORY", current.getRegistrationDate(), current.isActive()));
        };

        LoginResult result = login.execute(EMAIL, PASSWORD);

        assertThat(result.accessToken()).isEqualTo("access-" + SALES_ID + "-INVENTORY");
    }

    @Test
    void theAccessTokenIsIssuedOnlyAfterTheRefreshCredentialWasPersisted() {
        login.execute(EMAIL, PASSWORD);

        assertThat(events).containsExactly("refresh", "access:SALESPERSON:stored=1");
    }

    @Test
    void theSlowVerificationRunsOutsideTheFence_neverInsideTheTransactionOfThePort() {
        login.execute(EMAIL, PASSWORD);
        assertThat(catchThrowable(() -> login.execute(EMAIL, "not-the-password"))).isInstanceOf(InvalidCredentialsException.class);

        assertThat(verifications).isGreaterThanOrEqualTo(2);
        assertThat(verifiedInsideTheFence).as("bcrypt never runs while the port holds its transaction and lock").isFalse();
    }

    @Test
    void aWrongPassword_neverReachesThePersistencePort() {
        assertThat(catchThrowable(() -> login.execute(EMAIL, "not-the-password"))).isInstanceOf(InvalidCredentialsException.class);

        assertThat(issuance.calls).isZero();
    }

    @Test
    void theRefreshCredentialExpiresSevenDaysAhead() {
        login.execute(EMAIL, PASSWORD);

        assertThat(refreshTokens.hashToExpiry.get(HASH.hash("refresh-1"))).isEqualTo(NOW.plus(REFRESH_TTL));
    }
}
