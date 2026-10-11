package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.usecase.Fakes.FakeRefreshTokenStore;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.HASH;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.NOW;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LogoutUseCaseTest {

    private static final String OWNER = "u-1";

    private FakeRefreshTokenStore store;
    private LogoutUseCase logout;

    @BeforeEach
    void setUp() {
        store = new FakeRefreshTokenStore();
        logout = new LogoutUseCase(store, HASH);
    }

    private static AuthenticatedCaller caller(String subject, String role) {
        return new AuthenticatedCaller(subject, Set.of(role), Set.of());
    }

    @Test
    void theCallersOwnToken_isRevoked_andTheResultSaysLoggedOut() {
        store.save(HASH.hash("raw"), OWNER, NOW.plusSeconds(60));

        LogoutResult result = logout.execute(caller(OWNER, "ADMIN"), "raw");

        assertThat(result.loggedOut()).isTrue();
        assertThat(store.hashToUser).doesNotContainKey(HASH.hash("raw"));
        assertThat(store.revokedHashes).containsExactly(HASH.hash("raw"));
    }

    @Test
    void anUnknownToken_answersTheSameResult_andRevokesNothing() {
        LogoutResult result = logout.execute(caller(OWNER, "ADMIN"), "never-issued");

        assertThat(result.loggedOut()).isTrue();
        assertThat(store.revokedHashes).isEmpty();
    }

    @Test
    void anExpiredToken_answersTheSameResult_andChangesNothing() {
        store.save(HASH.hash("expired"), OWNER, NOW.minusSeconds(1));

        LogoutResult result = logout.execute(caller(OWNER, "ADMIN"), "expired");

        assertThat(result.loggedOut()).isTrue();
        assertThat(store.hashToUser).containsKey(HASH.hash("expired"));
        assertThat(store.revokedHashes).isEmpty();
    }

    @Test
    void anAlreadyUsedToken_answersTheSameResult_andChangesNothing() {
        store.usedHashToUser.put(HASH.hash("used"), OWNER);
        store.usedHashToExpiry.put(HASH.hash("used"), NOW.plusSeconds(60));

        LogoutResult result = logout.execute(caller(OWNER, "ADMIN"), "used");

        assertThat(result.loggedOut()).isTrue();
        assertThat(store.revokedHashes).isEmpty();
    }

    @Test
    void someoneElsesToken_answersTheSameResult_andIsNotRevoked() {
        store.save(HASH.hash("theirs"), "u-2", NOW.plusSeconds(60));

        LogoutResult result = logout.execute(caller(OWNER, "ADMIN"), "theirs");

        assertThat(result.loggedOut()).isTrue();
        assertThat(store.hashToUser).containsEntry(HASH.hash("theirs"), "u-2");
        assertThat(store.revokedHashes).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ADMIN", "SALESPERSON", "INVENTORY"})
    void everyRoleOfAPerson_mayLogOut(String role) {
        store.save(HASH.hash("raw"), OWNER, NOW.plusSeconds(60));

        assertThat(logout.execute(caller(OWNER, role), "raw").loggedOut()).isTrue();
        assertThat(store.revokedHashes).containsExactly(HASH.hash("raw"));
    }

    @Test
    void aServiceCaller_isForbidden_andNothingIsRevoked() {
        store.save(HASH.hash("raw"), OWNER, NOW.plusSeconds(60));

        assertThatThrownBy(() -> logout.execute(caller(OWNER, "SERVICE"), "raw"))
            .isInstanceOf(ForbiddenException.class);
        assertThat(store.revokedHashes).isEmpty();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    void aMissingOrBlankToken_isAValidationErrorOnRefreshToken(String refreshToken) {
        assertThatThrownBy(() -> logout.execute(caller(OWNER, "ADMIN"), refreshToken))
            .isInstanceOfSatisfying(ValidationException.class, e ->
                assertThat(e.problems()).extracting(ValidationException.Problem::field).containsExactly("refreshToken"));
    }

    @Test
    void aServiceCaller_isForbiddenBeforeTheTokenIsEvenLookedAt() {
        assertThatThrownBy(() -> logout.execute(caller(OWNER, "SERVICE"), null))
            .isInstanceOf(ForbiddenException.class);
    }
}
