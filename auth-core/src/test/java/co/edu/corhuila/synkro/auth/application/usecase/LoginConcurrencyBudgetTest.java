package co.edu.corhuila.synkro.auth.application.usecase;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class LoginConcurrencyBudgetTest {
    @Test void rejectsWithoutWaitingAndRecoversOnlyWhenAHolderFinishes() {
        var budget = new LoginConcurrencyBudget(2, 1);
        var first = budget.acquire();
        var second = budget.acquire();
        assertThatThrownBy(budget::acquire).isInstanceOf(LoginThrottledException.class)
            .satisfies(e -> assertThat(((LoginThrottledException)e).retryAfterSeconds()).isEqualTo(1));
        first.close();
        var third = budget.acquire();
        first.close(); // repeated close must not invent another slot
        assertThatThrownBy(budget::acquire).isInstanceOf(LoginThrottledException.class);
        third.close(); second.close();
        try (var ignored = budget.acquire(); var also = budget.acquire()) {
            assertThatThrownBy(budget::acquire).isInstanceOf(LoginThrottledException.class);
        }
    }

    @Test void rejectsInvalidConfiguration() {
        assertThatIllegalArgumentException().isThrownBy(() -> new LoginConcurrencyBudget(0, 1));
        assertThatIllegalArgumentException().isThrownBy(() -> new LoginConcurrencyBudget(2, 0));
    }
}
