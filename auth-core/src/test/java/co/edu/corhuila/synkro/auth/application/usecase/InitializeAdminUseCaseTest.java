package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InitializeAdminUseCaseTest {

    private InitialAdminCommand command(String name, String email, String password, String operator, String correlation) {
        return new InitialAdminCommand(name, email, password, operator, correlation);
    }

    @Test
    void createsFixedActiveAdminWithHashedPasswordAndOperatorAttribution() {
        AtomicInteger writes = new AtomicInteger();
        InitialAdminStore store = (user, attribution) -> {
            writes.incrementAndGet();
            assertThat(user.getUserId()).satisfies(id -> UUID.fromString(id));
            assertThat(user.getName()).isEqualTo("Ana");
            assertThat(user.getEmail()).isEqualTo("ana@example.test");
            assertThat(user.getPasswordHash()).isEqualTo("hashed:" + Fakes.PASSWORD);
            assertThat(user.getRole()).isEqualTo("ADMIN");
            assertThat(user.isActive()).isTrue();
            assertThat(user.getRegistrationDate()).isEqualTo(Fakes.NOW);
            assertThat(attribution.auditId()).satisfies(id -> UUID.fromString(id));
            assertThat(attribution.operatorIdentity()).isEqualTo("deployment/angel");
            assertThat(attribution.correlationId()).isEqualTo("run-14");
            assertThat(attribution.occurredAt()).isEqualTo(Fakes.NOW);
            return new InitialAdminResult(true, user.getUserId());
        };
        var useCase = new InitializeAdminUseCase(store, Fakes.PASSWORD_HASHER, () -> UUID.randomUUID().toString(), Fakes.CLOCK);

        assertThat(useCase.execute(command("Ana", " Ana@Example.test ", Fakes.PASSWORD, "deployment/angel", "run-14")).created())
            .isTrue();
        assertThat(writes).hasValue(1);
    }

    @Test
    void returnsNoopWithoutDisclosingExistingUser() {
        var useCase = new InitializeAdminUseCase((u, a) -> new InitialAdminResult(false, null),
            Fakes.PASSWORD_HASHER, () -> UUID.randomUUID().toString(), Fakes.CLOCK);

        assertThat(useCase.execute(command("Ana", "ana@example.test", Fakes.PASSWORD, "operator", "run")))
            .isEqualTo(new InitialAdminResult(false, null));
    }

    @Test
    void validatesBeforeHashingIdsOrPersistence() {
        var useCase = new InitializeAdminUseCase((u, a) -> { throw new AssertionError("storage touched"); },
            new PasswordHasher() {
                public String hash(String p) { throw new AssertionError("hashing touched"); }
                public boolean matches(String p, String h) { throw new AssertionError(); }
            }, () -> { throw new AssertionError("ids touched"); }, Fakes.CLOCK);

        for (var invalid : List.of(
            command(null, "a@b.test", Fakes.PASSWORD, "op", "run"),
            command("x".repeat(151), "a@b.test", Fakes.PASSWORD, "op", "run"),
            command("Ana", "wrong", Fakes.PASSWORD, "op", "run"),
            command("Ana", "a@b.test", "short", "op", "run"),
            command("Ana", "a@b.test", "é".repeat(37), "op", "run"),
            command("Ana", "a@b.test", Fakes.PASSWORD, null, "run"),
            command("Ana", "a@b.test", Fakes.PASSWORD, " ", "run"),
            command("Ana", "a@b.test", Fakes.PASSWORD, "x".repeat(201), "run"),
            command("Ana", "a@b.test", Fakes.PASSWORD, "op\nforged", "run"),
            command("Ana", "a@b.test", Fakes.PASSWORD, "op", ""),
            command("Ana", "a@b.test", Fakes.PASSWORD, "op", "run\nforged"))) {
            assertThatThrownBy(() -> useCase.execute(invalid)).isInstanceOf(ValidationException.class)
                .hasMessage("validation failed");
        }
        assertThatThrownBy(() -> useCase.execute(null)).isInstanceOf(ValidationException.class);
    }

    @Test
    void commandStringNeverContainsRawInput() {
        assertThat(command("private-name", "private@email.test", "private-password", "op", "run").toString())
            .doesNotContain("private-name", "private@email.test", "private-password");
    }
}
