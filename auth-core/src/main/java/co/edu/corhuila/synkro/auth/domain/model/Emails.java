package co.edu.corhuila.synkro.auth.domain.model;

import java.util.Locale;

/** The one place that decides when two spellings of an email are the same address. */
public final class Emails {
    private Emails() {}

    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
