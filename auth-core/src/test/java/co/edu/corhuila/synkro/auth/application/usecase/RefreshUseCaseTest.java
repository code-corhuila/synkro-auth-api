package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.Fakes.FakeRefreshTokenStore;
import co.edu.corhuila.synkro.auth.application.usecase.Fakes.RecordingTokenIssuer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.HASH;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.REFRESH_TTL;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.user;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.users;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshUseCaseTest {

    private RecordingTokenIssuer issuer;
    private FakeRefreshTokenStore store;
    private LoginUseCase login;
    private RefreshUseCase refresh;

    @BeforeEach
    void setUp() {
        issuer = new RecordingTokenIssuer();
        store = new FakeRefreshTokenStore();
        var repo = users(user("ana@synkro.test", true));
        login = new LoginUseCase(repo, PASSWORD_HASHER, issuer, store, HASH, CLOCK, REFRESH_TTL);
        refresh = new RefreshUseCase(repo, issuer, store, HASH, CLOCK, REFRESH_TTL);
    }

    @Test
    void validToken_issuesNewAccessAndRefreshTokens() {
        LoginResult first = login.execute("ana@synkro.test", PASSWORD);

        LoginResult second = refresh.execute(first.refreshToken());

        assertThat(second.accessToken()).isNotBlank().isNotEqualTo(first.accessToken());
        assertThat(second.refreshToken()).isNotEqualTo(first.refreshToken());
        assertThat(issuer.accessRoles).containsExactly("ADMIN", "ADMIN");
    }

    @Test
    void rotation_leavesOnlyTheNewTokenHashStored() {
        LoginResult first = login.execute("ana@synkro.test", PASSWORD);

        LoginResult second = refresh.execute(first.refreshToken());

        assertThat(store.hashToUser).containsOnlyKeys(HASH.hash(second.refreshToken()));
    }

    @Test
    void usedToken_isInvalidated_soReplayIsRejected() {
        LoginResult first = login.execute("ana@synkro.test", PASSWORD);
        refresh.execute(first.refreshToken());

        assertThatThrownBy(() -> refresh.execute(first.refreshToken()))
            .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void rotatedToken_isStoredWithAFreshSevenDayExpiry() {
        LoginResult first = login.execute("ana@synkro.test", PASSWORD);

        LoginResult second = refresh.execute(first.refreshToken());

        assertThat(store.hashToExpiry.get(HASH.hash(second.refreshToken())))
            .isEqualTo(Fakes.NOW.plus(Duration.ofDays(7)));
    }

    @Test
    void unknownToken_isRejected() {
        assertThatThrownBy(() -> refresh.execute("never-issued"))
            .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void tokenOfADeactivatedUser_isRejected_andIssuesNothing() {
        var refreshForInactive = new RefreshUseCase(users(user("ana@synkro.test", false)), issuer, store, HASH, CLOCK, REFRESH_TTL);
        store.save(HASH.hash("raw"), "u-1", Fakes.NOW.plusSeconds(60));

        assertThatThrownBy(() -> refreshForInactive.execute("raw"))
            .isInstanceOf(InvalidCredentialsException.class);
        assertThat(issuer.accessSubjects).isEmpty();
    }

    @Test
    void tokenOfADeactivatedUser_leavesNoUsableTokenBehind() {
        var refreshForInactive = new RefreshUseCase(users(user("ana@synkro.test", false)), issuer, store, HASH, CLOCK, REFRESH_TTL);
        store.save(HASH.hash("raw"), "u-1", Fakes.NOW.plusSeconds(60));

        assertThatThrownBy(() -> refreshForInactive.execute("raw")).isInstanceOf(InvalidCredentialsException.class);

        assertThat(store.hashToUser).isEmpty();
    }

    @Test
    void rotation_isOneStoreStep_soAnInvalidTokenStoresNoReplacement() {
        assertThatThrownBy(() -> refresh.execute("never-issued")).isInstanceOf(InvalidCredentialsException.class);

        assertThat(store.hashToUser).isEmpty();
    }

    @Test
    void reusedToken_isRejected_andRevokesEveryActiveTokenOfItsOwner() {
        LoginResult first = login.execute("ana@synkro.test", PASSWORD);
        LoginResult second = refresh.execute(first.refreshToken());

        assertThatThrownBy(() -> refresh.execute(first.refreshToken()))
            .isInstanceOf(InvalidCredentialsException.class);

        assertThat(store.revokedUsers).containsExactly("u-1");
        assertThat(store.hashToUser).as("the token issued by the legitimate rotation").doesNotContainKey(HASH.hash(second.refreshToken()));
    }

    @Test
    void reusedToken_leavesTheTokensOfOtherUsersUsable() {
        LoginResult first = login.execute("ana@synkro.test", PASSWORD);
        store.save(HASH.hash("someone-else"), "u-2", Fakes.NOW.plusSeconds(60));
        refresh.execute(first.refreshToken());

        assertThatThrownBy(() -> refresh.execute(first.refreshToken())).isInstanceOf(InvalidCredentialsException.class);

        assertThat(store.hashToUser).containsEntry(HASH.hash("someone-else"), "u-2");
    }

    @Test
    void unknownToken_revokesNothing() {
        assertThatThrownBy(() -> refresh.execute("never-issued")).isInstanceOf(InvalidCredentialsException.class);

        assertThat(store.revokedUsers).isEmpty();
    }

    @Test
    void expiredToken_revokesNothing() {
        store.save(HASH.hash("expired"), "u-1", Fakes.NOW.minusSeconds(1));

        assertThatThrownBy(() -> refresh.execute("expired")).isInstanceOf(InvalidCredentialsException.class);

        assertThat(store.revokedUsers).isEmpty();
    }

    @Test
    void rotatedTokenThatAlsoExpired_revokesNothing() {
        store.usedHashToUser.put(HASH.hash("old"), "u-1");
        store.usedHashToExpiry.put(HASH.hash("old"), Fakes.NOW.minusSeconds(1));

        assertThatThrownBy(() -> refresh.execute("old")).isInstanceOf(InvalidCredentialsException.class);

        assertThat(store.revokedUsers).isEmpty();
    }

    @Test
    void validToken_stillRotates_andRevokesNothing() {
        LoginResult first = login.execute("ana@synkro.test", PASSWORD);

        LoginResult second = refresh.execute(first.refreshToken());

        assertThat(store.hashToUser).containsKey(HASH.hash(second.refreshToken()));
        assertThat(store.revokedUsers).isEmpty();
    }
}
