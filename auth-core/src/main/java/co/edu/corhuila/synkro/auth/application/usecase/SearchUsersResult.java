package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.util.List;

/** The page actually served, with the page/limit the validator resolved (defaults included). */
public record SearchUsersResult(List<SystemUser> items, long total, int page, int limit) {
}
