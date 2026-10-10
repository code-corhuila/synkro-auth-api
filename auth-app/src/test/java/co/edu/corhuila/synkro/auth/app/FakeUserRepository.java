package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.List;
import java.util.Optional;

/**
 * Test double with one user per role, so the HTTP tests that exercise tokens and routes run
 * without a database. These credentials exist only in test code; production reads
 * auth_schema.system_user.
 */
class FakeUserRepository implements UserRepository {

    private final List<SystemUser> users;

    FakeUserRepository() {
        BcryptPasswordHasher hasher = new BcryptPasswordHasher();
        this.users = List.of(
            new SystemUser("00000000-0000-0000-0000-000000000001", "Test Admin", "admin@synkro.test",
                hasher.hash("admin-dev-password"), "ADMIN", true),
            new SystemUser("00000000-0000-0000-0000-000000000002", "Test Salesperson", "sales@synkro.test",
                hasher.hash("sales-dev-password"), "SALESPERSON", true),
            new SystemUser("00000000-0000-0000-0000-000000000003", "Test Inventory", "inventory@synkro.test",
                hasher.hash("inventory-dev-password"), "INVENTORY", true));
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return users.stream().filter(u -> u.getEmail().equals(email)).findFirst();
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        return users.stream().filter(u -> u.getUserId().equals(userId)).findFirst();
    }
}
