package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

/**
 * {@code signedToken} is present only when {@code created} is true: a replay answers with the metadata
 * alone. toString leaves the token out so that a log line can never carry it.
 */
public record IssueServiceTokenResult(ServiceToken token, String signedToken, boolean created) {

    static IssueServiceTokenResult created(ServiceToken token, String signedToken) {
        return new IssueServiceTokenResult(token, signedToken, true);
    }

    static IssueServiceTokenResult replayed(ServiceToken token) {
        return new IssueServiceTokenResult(token, null, false);
    }

    @Override
    public String toString() {
        return "IssueServiceTokenResult[tokenId=" + token.tokenId() + ", created=" + created + "]";
    }
}
