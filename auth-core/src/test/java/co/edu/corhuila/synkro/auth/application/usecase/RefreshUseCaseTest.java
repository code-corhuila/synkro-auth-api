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
        login = new LoginUseCase(repo, PASSWORD_HASHER, issuer, store, HASH);
        refresh = new RefreshUseCase(repo, issuer, store, HASH);
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
    void unknownToken_isRejected() {
        assertThatThrownBy(() -> refresh.execute("never-issued"))
            .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void tokenOfADeactivatedUser_isRejected_andIssuesNothing() {
        var refreshForInactive = new RefreshUseCase(users(user("ana@synkro.test", false)), issuer, store, HASH);
        store.save(HASH.hash("raw"), "u-1");

        assertThatThrownBy(() -> refreshForInactive.execute("raw"))
            .isInstanceOf(InvalidCredentialsException.class);
        assertThat(issuer.accessSubjects).isEmpty();
    }
}
