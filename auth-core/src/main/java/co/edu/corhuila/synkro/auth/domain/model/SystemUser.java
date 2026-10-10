package co.edu.corhuila.synkro.auth.domain.model;

import java.time.Instant;
import java.util.Set;

public class SystemUser {
    // SERVICE is deliberately absent: it exists only inside service tokens and is
    // never assigned to a person (ADR-006).
    private static final Set<String> VALID_ROLES = Set.of("ADMIN", "SALESPERSON", "INVENTORY");

    private final String userId;
    private final String name;
    private final String email;
    private final String passwordHash;
    private final String role;
    private final Instant registrationDate;
    private final boolean active;

    public SystemUser(String userId, String name, String email, String passwordHash, String role,
                      Instant registrationDate, boolean active) {
        if (role == null || !VALID_ROLES.contains(role)) {
            throw new IllegalArgumentException(role + " is not a valid person role");
        }
        this.userId = userId;
        this.name = name;
        this.email = email;
        this.passwordHash = passwordHash;
        this.role = role;
        this.registrationDate = registrationDate;
        this.active = active;
    }

    public static boolean isPersonRole(String role) {
        return role != null && VALID_ROLES.contains(role);
    }

    public String getUserId() { return userId; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public String getRole() { return role; }
    public Instant getRegistrationDate() { return registrationDate; }
    public boolean isActive() { return active; }
}
