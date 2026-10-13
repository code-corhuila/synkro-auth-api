package co.edu.corhuila.synkro.auth.application.usecase;

/** A domain rule rejects an otherwise well-formed request; it names the field that breaks it. */
public class BusinessRuleViolationException extends RuntimeException {
    private final String field;

    public BusinessRuleViolationException(String field, String message) {
        super(message);
        this.field = field;
    }

    public String field() {
        return field;
    }
}
