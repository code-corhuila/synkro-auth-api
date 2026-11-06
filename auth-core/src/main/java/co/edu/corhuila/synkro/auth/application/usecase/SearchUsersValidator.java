package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository.SearchCriteria;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException.Problem;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.ArrayList;
import java.util.List;

/** The limits of UserSearchRequest in synkro-auth-api.yaml (HU-AUTH-18, issue #297). */
final class SearchUsersValidator {
    private static final int Q_MAX_LENGTH = 150;
    private static final int DEFAULT_PAGE = 1;
    private static final int DEFAULT_LIMIT = 20;
    private static final int MAX_LIMIT = 100;

    private SearchUsersValidator() {}

    static SearchCriteria validate(SearchUsersCommand command) {
        List<Problem> problems = new ArrayList<>();
        checkQuery(problems, command.q());
        checkRole(problems, command.role());
        checkPage(problems, command.page());
        checkLimit(problems, command.limit());
        if (!problems.isEmpty()) {
            throw new ValidationException(problems);
        }
        return new SearchCriteria(normalizedQuery(command.q()), command.role(),
            command.page() == null ? DEFAULT_PAGE : command.page(),
            command.limit() == null ? DEFAULT_LIMIT : command.limit());
    }

    private static String normalizedQuery(String q) {
        if (q == null) {
            return null;
        }
        String trimmed = q.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static void checkQuery(List<Problem> problems, String q) {
        if (q != null && q.length() > Q_MAX_LENGTH) {
            problems.add(new Problem("q", "The field q must have at most 150 characters"));
        }
    }

    private static void checkRole(List<Problem> problems, String role) {
        if (role != null && !SystemUser.isPersonRole(role)) {
            problems.add(new Problem("role", "The field role must be ADMIN, SALESPERSON or INVENTORY"));
        }
    }

    private static void checkPage(List<Problem> problems, Integer page) {
        if (page != null && page < 1) {
            problems.add(new Problem("page", "The field page must be at least 1"));
        }
    }

    private static void checkLimit(List<Problem> problems, Integer limit) {
        if (limit != null && (limit < 1 || limit > MAX_LIMIT)) {
            problems.add(new Problem("limit", "The field limit must be 1 to 100"));
        }
    }
}
