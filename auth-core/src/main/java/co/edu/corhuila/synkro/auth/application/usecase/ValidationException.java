package co.edu.corhuila.synkro.auth.application.usecase;

import java.util.List;

/** The input breaks the contract before any rule or storage is involved; one problem per offending field. */
public class ValidationException extends RuntimeException {
    public record Problem(String field, String message) {}

    private final transient List<Problem> problems;

    public ValidationException(List<Problem> problems) {
        super("validation failed");
        this.problems = List.copyOf(problems);
    }

    public List<Problem> problems() {
        return problems;
    }
}
