package co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.List;
import java.util.Optional;

/**
 * TEMPORARY. Replaced by a real Postgres adapter once synkro-auth-db has a
 * system_user table.
 *
 * Seeds one user per role with a bcrypt-hashed password, for development and for
 * this story's own tests. It is never a stand-in for real user management: nothing
 * can create, change or deactivate a user, and every restart resets it. The
 * plaintext development passwords are documented only in the README's
 * "Development" section, and are never logged or returned by any endpoint.
 */
public class InMemorySeededUserRepository implements UserRepository {

    private final List<SystemUser> users;

    public InMemorySeededUserRepository(BcryptPasswordHasher hasher) {
        this.users = List.of(
            new SystemUser("00000000-0000-0000-0000-000000000001", "Dev Admin", "admin@synkro.test",
                hasher.hash("admin-dev-password"), "ADMIN", true),
            new SystemUser("00000000-0000-0000-0000-000000000002", "Dev Salesperson", "sales@synkro.test",
                hasher.hash("sales-dev-password"), "SALESPERSON", true),
            new SystemUser("00000000-0000-0000-0000-000000000003", "Dev Inventory", "inventory@synkro.test",
                hasher.hash("inventory-dev-password"), "INVENTORY", true));
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return users.stream().filter(u -> u.getEmail().equalsIgnoreCase(email)).findFirst();
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        return users.stream().filter(u -> u.getUserId().equals(userId)).findFirst();
    }
}
