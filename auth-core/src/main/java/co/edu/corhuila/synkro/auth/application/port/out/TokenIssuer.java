package co.edu.corhuila.synkro.auth.application.port.out;

public interface TokenIssuer {
    String issueAccessToken(String subject, String role);

    /** Opaque, not a JWT: it is stored hashed and never decoded. */
    String issueRefreshToken();
}
