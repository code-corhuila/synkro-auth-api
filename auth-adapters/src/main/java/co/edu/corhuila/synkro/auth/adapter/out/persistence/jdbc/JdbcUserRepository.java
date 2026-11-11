package co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** Repository over auth_schema.system_user: it reads users; JdbcUserRegistrationStore writes them. */
public class JdbcUserRepository implements UserRepository {

    private static final String SELECT_USER =
        "SELECT " + SystemUserRows.COLUMNS + " FROM auth_schema.system_user u ";
    private static final String BY_EMAIL = SELECT_USER + "WHERE u.email = ?";
    private static final String BY_ID = SELECT_USER + "WHERE u.user_id = ?";

    private static final String SEARCH_FROM = "FROM auth_schema.system_user u";
    // ESCAPE '\' makes a literal "%" or "_" in the search term match itself, not act as a
    // wildcard: HU-AUTH-18/#297 promises a plain substring match, never pattern syntax.
    private static final String SEARCH_TEXT_FILTER = "(u.name ILIKE ? ESCAPE '\\' OR u.email ILIKE ? ESCAPE '\\')";
    private static final String SEARCH_ROLE_FILTER = "u.role = ?";
    private static final String SEARCH_ORDER = " ORDER BY u.registration_date DESC, u.user_id ASC LIMIT ? OFFSET ?";

    private final JdbcTemplate jdbc;

    public JdbcUserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<SystemUser> findByEmail(String email) {
        return jdbc.query(BY_EMAIL, SystemUserRows.TO_USER, email).stream().findFirst();
    }

    @Override
    public Optional<SystemUser> findById(String userId) {
        return parseUuid(userId).flatMap(id -> jdbc.query(BY_ID, SystemUserRows.TO_USER, id).stream().findFirst());
    }

    @Override
    public SearchResult search(SearchCriteria criteria) {
        List<String> conditions = new ArrayList<>();
        List<Object> args = new ArrayList<>();
        if (criteria.query() != null) {
            conditions.add(SEARCH_TEXT_FILTER);
            String pattern = literalLikePattern(criteria.query());
            args.add(pattern);
            args.add(pattern);
        }
        if (criteria.role() != null) {
            conditions.add(SEARCH_ROLE_FILTER);
            args.add(criteria.role());
        }
        String where = conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions);

        long total = jdbc.queryForObject("SELECT count(*) " + SEARCH_FROM + where, Long.class, args.toArray());

        List<Object> pageArgs = new ArrayList<>(args);
        pageArgs.add(criteria.limit());
        pageArgs.add((long) (criteria.page() - 1) * criteria.limit());
        List<SystemUser> items = jdbc.query(
            "SELECT " + SystemUserRows.SEARCH_COLUMNS + " " + SEARCH_FROM + where + SEARCH_ORDER,
            SystemUserRows.TO_SEARCH_RESULT, pageArgs.toArray());

        return new SearchResult(items, total);
    }

    // A literal substring, never a pattern: every character ILIKE treats specially is escaped first.
    private static String literalLikePattern(String query) {
        String escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return "%" + escaped + "%";
    }

    private static Optional<UUID> parseUuid(String value) {
        try {
            return Optional.of(UUID.fromString(value));
        } catch (IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }
}
