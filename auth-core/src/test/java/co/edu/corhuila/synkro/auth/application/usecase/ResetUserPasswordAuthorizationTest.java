package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static co.edu.corhuila.synkro.auth.application.usecase.FakePasswordResetStore.SALES_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.ADMIN_CALLER;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CLOCK;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.CORRELATION_ID;
import static co.edu.corhuila.synkro.auth.application.usecase.Fakes.PASSWORD_HASHER;
import static co.edu.corhuila.synkro.auth.application.usecase.ResetUserPasswordUseCaseTest.command;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Only a human ADMIN whose account is there and active may reset a password. Everyone else is refused before the key,
 * the target or the body is looked at: a refused caller learns nothing about any of them.
 */
class ResetUserPasswordAuthorizationTest {

    private FakePasswordResetStore store;
    private ResetUserPasswordUseCase reset;

    @BeforeEach
    void setUp() {
        store = new FakePasswordResetStore();
        reset = new ResetUserPasswordUseCase(store, store, PASSWORD_HASHER, () -> "audit-1", CLOCK, Fakes.IGNORED_RESET_ATTEMPTS);
    }

    private void assertNothingTouched() {
        assertThat(store.lookups).isZero();
        assertThat(store.resetCalls).isZero();
        assertThat(store.audits).isEmpty();
        assertThat(store.revokedOwners).isEmpty();
    }

    @Test
    void noCaller_isUnauthenticated() {
        assertThatThrownBy(() -> reset.execute(null, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOf(UnauthenticatedException.class);

        assertNothingTouched();
    }

    @Test
    void aServiceToken_isForbidden_evenWithTheAdminRole() {
        AuthenticatedCaller service = new AuthenticatedCaller(ADMIN_CALLER.subject(), Set.of(Roles.SERVICE, Roles.ADMIN), Set.of());

        assertThatThrownBy(() -> reset.execute(service, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOf(ForbiddenException.class);

        assertNothingTouched();
    }

    @Test
    void aSalespersonOrInventoryCaller_isForbidden() {
        for (String role : new String[] {Roles.SALESPERSON, Roles.INVENTORY}) {
            AuthenticatedCaller caller = new AuthenticatedCaller(FakePasswordResetStore.SALES_ID, Set.of(role), Set.of());

            assertThatThrownBy(() -> reset.execute(caller, CORRELATION_ID, command(FakePasswordResetStore.INVENTORY_ID)))
                .isInstanceOf(ForbiddenException.class);
        }

        assertNothingTouched();
    }

    @Test
    void aCallerWithNoRoles_isForbidden() {
        AuthenticatedCaller nobody = new AuthenticatedCaller(ADMIN_CALLER.subject(), Set.of(), Set.of());

        assertThatThrownBy(() -> reset.execute(nobody, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOf(ForbiddenException.class);

        assertNothingTouched();
    }

    @Test
    void aWellFormedAdminTokenForAnAccountThatDoesNotExist_isForbidden_withAGenericMessage() {
        AuthenticatedCaller ghost = new AuthenticatedCaller(FakePasswordResetStore.MISSING_ID, Set.of(Roles.ADMIN), Set.of());

        assertThatThrownBy(() -> reset.execute(ghost, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOfSatisfying(ForbiddenException.class, e ->
                assertThat(e.getMessage()).doesNotContain(FakePasswordResetStore.MISSING_ID, SALES_ID));

        assertNothingTouched();
    }

    @Test
    void anAdminWhoseAccountIsNoLongerActive_isForbidden() {
        store.add(ADMIN_CALLER.subject(), "ADMIN", false);

        assertThatThrownBy(() -> reset.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOf(ForbiddenException.class);

        assertNothingTouched();
    }

    @Test
    void aLookupThatFails_isAFailure_notAnAbsentActor() {
        FakePasswordResetStore broken = new FakePasswordResetStore() {
            @Override
            public java.util.Optional<co.edu.corhuila.synkro.auth.domain.model.SystemUser> findById(String userId) {
                throw new IllegalStateException("database unavailable");
            }
        };
        ResetUserPasswordUseCase failing = new ResetUserPasswordUseCase(broken, broken, PASSWORD_HASHER, () -> "audit-1", CLOCK,
            Fakes.IGNORED_RESET_ATTEMPTS);

        assertThatThrownBy(() -> failing.execute(ADMIN_CALLER, CORRELATION_ID, command(SALES_ID)))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void authorizationComesBeforeValidation_soAForbiddenCallerLearnsNothingAboutTheRequest() {
        AuthenticatedCaller sales = new AuthenticatedCaller(SALES_ID, Set.of(Roles.SALESPERSON), Set.of());
        ResetUserPasswordCommand broken = new ResetUserPasswordCommand("not-an-id", null, "x", "y");

        assertThatThrownBy(() -> reset.execute(sales, CORRELATION_ID, broken)).isInstanceOf(ForbiddenException.class);
    }
}
