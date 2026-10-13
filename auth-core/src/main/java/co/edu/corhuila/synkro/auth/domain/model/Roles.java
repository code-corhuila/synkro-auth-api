package co.edu.corhuila.synkro.auth.domain.model;

/** Role names that appear in the {@code roles} claim of an access token. */
public final class Roles {
    public static final String ADMIN = "ADMIN";
    public static final String SALESPERSON = "SALESPERSON";
    public static final String INVENTORY = "INVENTORY";
    /** Token-only role of service tokens (ADR-006); never assigned to a person. */
    public static final String SERVICE = "SERVICE";

    private Roles() {}
}
