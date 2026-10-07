package co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InMemorySeededUserRepositoryTest {

    private static BcryptPasswordHasher hasher;
    private static InMemorySeededUserRepository repository;

    @BeforeAll
    static void seed() {
        hasher = new BcryptPasswordHasher();
        repository = new InMemorySeededUserRepository(hasher);
    }

    @Test
    void seedsExactlyOneActiveUserPerRole() {
        List<String> roles = List.of(
            repository.findByEmail("admin@synkro.test").orElseThrow().getRole(),
            repository.findByEmail("sales@synkro.test").orElseThrow().getRole(),
            repository.findByEmail("inventory@synkro.test").orElseThrow().getRole());

        assertThat(roles).containsExactly("ADMIN", "SALESPERSON", "INVENTORY");
        assertThat(repository.findByEmail("admin@synkro.test").orElseThrow().isActive()).isTrue();
    }

    @Test
    void storesBcryptHashes_notPlaintext() {
        SystemUser admin = repository.findByEmail("admin@synkro.test").orElseThrow();

        assertThat(admin.getPasswordHash()).startsWith("$2").doesNotContain("admin-dev-password");
        assertThat(hasher.matches("admin-dev-password", admin.getPasswordHash())).isTrue();
    }

    @Test
    void eachDocumentedDevPasswordUnlocksItsOwnUserOnly() {
        assertThat(hasher.matches("sales-dev-password",
            repository.findByEmail("sales@synkro.test").orElseThrow().getPasswordHash())).isTrue();
        assertThat(hasher.matches("inventory-dev-password",
            repository.findByEmail("inventory@synkro.test").orElseThrow().getPasswordHash())).isTrue();
        assertThat(hasher.matches("sales-dev-password",
            repository.findByEmail("admin@synkro.test").orElseThrow().getPasswordHash())).isFalse();
    }

    @Test
    void findById_returnsTheSameUser() {
        SystemUser admin = repository.findByEmail("admin@synkro.test").orElseThrow();

        assertThat(repository.findById(admin.getUserId())).containsSame(admin);
    }

    @Test
    void unknownEmailOrId_isEmpty() {
        assertThat(repository.findByEmail("ghost@synkro.test")).isEmpty();
        assertThat(repository.findById("ghost")).isEmpty();
    }
}
