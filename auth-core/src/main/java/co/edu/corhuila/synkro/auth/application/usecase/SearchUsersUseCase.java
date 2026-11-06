package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.AuthenticatedCaller;
import co.edu.corhuila.synkro.auth.domain.model.Roles;

/** Bounded, paginated ADMIN user search over system_user (HU-AUTH-18, issue #297). */
public class SearchUsersUseCase {
    private final UserRepository users;

    public SearchUsersUseCase(UserRepository users) {
        this.users = users;
    }

    public SearchUsersResult execute(AuthenticatedCaller caller, SearchUsersCommand command) {
        requireHumanAdmin(caller);
        UserRepository.SearchCriteria criteria = SearchUsersValidator.validate(command);
        UserRepository.SearchResult result = users.search(criteria);
        return new SearchUsersResult(result.items(), result.total(), criteria.page(), criteria.limit());
    }

    private static void requireHumanAdmin(AuthenticatedCaller caller) {
        if (caller == null) {
            throw new UnauthenticatedException();
        }
        RoleGuard.requireAnyRole(caller, "search users", Roles.ADMIN);
    }
}
