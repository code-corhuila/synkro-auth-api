package co.edu.corhuila.synkro.auth.application.port.out;

/** One-way digest applied to refresh tokens before they are stored. */
public interface HashFunction {
    String hash(String value);
}
