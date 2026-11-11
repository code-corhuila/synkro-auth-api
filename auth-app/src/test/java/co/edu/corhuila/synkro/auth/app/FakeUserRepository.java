package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Test double with one user per role, so the HTTP tests that exercise tokens and routes run
 * without a database. These credentials exist only in test code; production reads
 * auth_schema.system_user.
 */
class FakeUserRepository implements UserRepository {

    private static final Instant REGISTERED = Instant.parse("2026-01-01T00:00:00Z");

    private final List<SystemUser> users;

    FakeUserRepository() {
        BcryptPasswordHasher hasher = new BcryptPasswordHasher();
        this.users = List.of(
            new SystemUser("00000000-0000-0000-0000-000000000001", "Test Admin", "admin@synkro.test",
                hasher.hash("admin-dev-password"), "ADMIN", REGISTERED, true),
            new SystemUser("00000000-0000-0000-0000-000000000002", "Test Salesperson", "sales@synkro.test",
                hasher.hash("sales-dev-password"), "SALESPERSON", REGISTERED, true),
            new SystemUser("00000000-0000-0000-0000-000000000003", "Test Inventory", "inventory@synkro.test",
                hasher.hash("inventory-dev-password"), "INVENTORY", REGISTERED, true));
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return users.stream().filter(u -> u.getEmail().equals(email)).findFirst();
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        return users.stream().filter(u -> u.getUserId().equals(userId)).findFirst();
    }

    @Override
    public SearchResult search(SearchCriteria criteria) {
        List<SystemUser> matches = new java.util.ArrayList<>(users);
        matches.sort(Comparator.comparing(SystemUser::getRegistrationDate).reversed().thenComparing(SystemUser::getUserId));
        matches.removeIf(u -> criteria.role() != null && !criteria.role().equals(u.getRole()));
        if (criteria.query() != null) {
            String needle = criteria.query().toLowerCase(Locale.ROOT);
            matches.removeIf(u -> !u.getName().toLowerCase(Locale.ROOT).contains(needle)
                && !u.getEmail().toLowerCase(Locale.ROOT).contains(needle));
        }
        int from = Math.min((criteria.page() - 1) * criteria.limit(), matches.size());
        int to = Math.min(from + criteria.limit(), matches.size());
        return new SearchResult(matches.subList(from, to), matches.size());
    }
}
