package co.edu.corhuila.synkro.auth.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The table of ADR-006 Decision 2, written out literally. Adding or removing a permission, or a
 * service, makes these tests fail until the ADR is updated and this file is edited in the same review.
 */
class ServiceAccountTest {

    @Test
    void thereAreExactlyTwoServices() {
        assertThat(Arrays.stream(ServiceAccount.values()).map(ServiceAccount::serviceName))
            .containsExactlyInAnyOrder("synkro-workflow", "synkro-worker");
    }

    @Test
    void theWorkflowHasExactlyItsFourPermissions() {
        assertThat(ServiceAccount.WORKFLOW.permissions())
            .containsExactlyInAnyOrder("customers:read", "stock:reserve", "stock:release", "sales:register")
            .hasSize(4);
    }

    @Test
    void theWorkerHasExactlyItsThreePermissions() {
        assertThat(ServiceAccount.WORKER.permissions())
            .containsExactlyInAnyOrder("products:read", "stock-alerts:read", "stock-alerts:write")
            .hasSize(3);
    }

    @Test
    void aServiceIsFoundByItsExactName() {
        assertThat(ServiceAccount.fromName("synkro-workflow")).contains(ServiceAccount.WORKFLOW);
        assertThat(ServiceAccount.fromName("synkro-worker")).contains(ServiceAccount.WORKER);
    }

    @Test
    void anUnknownMisspelledOrMissingNameIsRejected() {
        for (String name : new String[] {null, "", " ", "synkro-sales", "SYNKRO-WORKFLOW", "synkro-workflow ", "workflow"}) {
            assertThat(ServiceAccount.fromName(name)).as("name: %s", name).isEmpty();
        }
    }

    @Test
    void thePermissionListsCannotBeChangedByACaller() {
        List<String> permissions = ServiceAccount.WORKFLOW.permissions();

        assertThatThrownBy(() -> permissions.add("users:manage")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void noServicePermissionBelongsToAPersonOnlyRole() {
        for (ServiceAccount account : ServiceAccount.values()) {
            assertThat(account.permissions()).isNotEmpty().doesNotContain("users:manage", "sales:create", "products:write");
        }
    }
}
