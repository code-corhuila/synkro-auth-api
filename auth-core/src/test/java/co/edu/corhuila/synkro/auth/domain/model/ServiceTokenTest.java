package co.edu.corhuila.synkro.auth.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class ServiceTokenTest {

    private static final Instant ISSUED_AT = Instant.parse("2026-03-01T10:15:30Z");

    @Test
    void aTokenExpiresExactlyThirtyDaysAfterItIsIssued() {
        ServiceToken token = ServiceToken.issue(ServiceAccount.WORKER, "token-1", "admin-1", ISSUED_AT);

        assertThat(token.issuedAt()).isEqualTo(ISSUED_AT);
        assertThat(token.expiresAt()).isEqualTo(ISSUED_AT.plus(Duration.ofDays(30)));
        assertThat(ServiceToken.LIFETIME).isEqualTo(Duration.ofDays(30));
    }

    @Test
    void aTokenCarriesTheFixedPermissionsOfItsServiceAndItsNameAsService() {
        ServiceToken workflow = ServiceToken.issue(ServiceAccount.WORKFLOW, "token-1", "admin-1", ISSUED_AT);
        ServiceToken worker = ServiceToken.issue(ServiceAccount.WORKER, "token-2", "admin-1", ISSUED_AT);

        assertThat(workflow.service()).isEqualTo("synkro-workflow");
        assertThat(workflow.permissions()).containsExactlyInAnyOrderElementsOf(ServiceAccount.WORKFLOW.permissions());
        assertThat(worker.service()).isEqualTo("synkro-worker");
        assertThat(worker.permissions()).containsExactlyInAnyOrderElementsOf(ServiceAccount.WORKER.permissions());
    }

    @Test
    void theIdentifiersAreKeptAsGiven() {
        ServiceToken token = ServiceToken.issue(ServiceAccount.WORKER, "token-9", "admin-7", ISSUED_AT);

        assertThat(token.tokenId()).isEqualTo("token-9");
        assertThat(token.issuedBy()).isEqualTo("admin-7");
    }
}
