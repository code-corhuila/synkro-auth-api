package co.edu.corhuila.synkro.auth.application.port.out;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.List;
import java.util.Optional;

public interface UserRepository {
    Optional<SystemUser> findByEmail(String email);

    // Refresh only knows the userId stored beside the token hash, and needs the
    // user's current role and active flag to issue a fresh access token.
    Optional<SystemUser> findById(String userId);

    /**
     * Bounded, paginated ADMIN directory search (HU-AUTH-18, issue #297). Ordered by
     * registrationDate descending with userId ascending as a tie-break, so the page
     * sequence stays stable even when two users share a registration timestamp.
     */
    SearchResult search(SearchCriteria criteria);

    /**
     * {@code query} is a literal, case-insensitive substring of name or email, or null for no text
     * filter. {@code role} narrows to one human role, or null for every role. {@code page} is 1-based.
     */
    record SearchCriteria(String query, String role, int page, int limit) {}

    record SearchResult(List<SystemUser> items, long total) {}
}
