package co.edu.corhuila.synkro.auth.app;

import java.util.List;

public class RequestValidationException extends RuntimeException {
    private final transient List<ApiExceptionHandler.FieldProblem> problems;

    public RequestValidationException(List<ApiExceptionHandler.FieldProblem> problems) {
        super("request validation failed");
        this.problems = problems;
    }

    public List<ApiExceptionHandler.FieldProblem> problems() {
        return problems;
    }
}
