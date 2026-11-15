package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.LoginAttemptStore;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import java.util.function.Function;
import static org.assertj.core.api.Assertions.*;

class AccountLoginProtectionTest {
    final MutableClock clock=new MutableClock();
    final FakeStore store=new FakeStore();
    final AccountLoginProtection guard=new AccountLoginProtection(store, value->value,clock,3,60,30,120,600);
    LoginResult bad(){throw new InvalidCredentialsException();}
    LoginResult good(){return new LoginResult("access","refresh");}
    void fail(String account){assertThatThrownBy(()->guard.execute(account,this::bad)).isInstanceOf(InvalidCredentialsException.class);}

    @Test void normalLoginSucceedsAndUnknownAccountsHaveTheSameFailureSequence() {
        assertThat(guard.execute("known@example.test",this::good).accessToken()).isEqualTo("access");
        for(String key:List.of("known@example.test","unknown@example.test")) {
            for(int i=0;i<3;i++)fail(key);
            assertThatThrownBy(()->guard.execute(key,this::bad)).isInstanceOf(LoginThrottledException.class);
        }
    }
    @Test void normalizedAccountsShareTheCounterButAnotherAccountDoesNot() {
        fail(" Employee@example.test ");fail("employee@EXAMPLE.test");fail("employee@example.test");
        assertThatThrownBy(()->guard.execute("EMPLOYEE@example.test",this::good)).isInstanceOf(LoginThrottledException.class);
        assertThat(guard.execute("other@example.test",this::good).accessToken()).isEqualTo("access");
        assertThat(store.states).containsOnlyKeys("employee@example.test");
    }
    @Test void blockedRequestsDoNotMoveDeadlineOrRetentionAndRoundUpRemainingSeconds() {
        for(int i=0;i<3;i++)fail("a@example.test");
        var before=store.states.get("a@example.test");
        clock.advance(Duration.ofMillis(29_100));
        assertThatThrownBy(()->guard.execute("a@example.test",this::good)).isInstanceOf(LoginThrottledException.class)
            .satisfies(e->assertThat(((LoginThrottledException)e).retryAfterSeconds()).isEqualTo(1));
        assertThat(store.states.get("a@example.test")).isEqualTo(before);
        clock.advance(Duration.ofMillis(900));
        assertThat(guard.execute("a@example.test",this::good).accessToken()).isEqualTo("access");
        assertThat(store.states).isEmpty();
    }
    @Test void progressionCapsAndSuccessResetsIt() {
        for(int seconds:List.of(30,60,120,120)) {
            for(int i=0;i<3;i++)fail("a@example.test");
            assertThatThrownBy(()->guard.execute("a@example.test",this::bad))
                .satisfies(e->assertThat(((LoginThrottledException)e).retryAfterSeconds()).isEqualTo(seconds));
            clock.advance(Duration.ofSeconds(seconds));
        }
        guard.execute("a@example.test",this::good);
        for(int i=0;i<3;i++)fail("a@example.test");
        assertThatThrownBy(()->guard.execute("a@example.test",this::bad))
            .satisfies(e->assertThat(((LoginThrottledException)e).retryAfterSeconds()).isEqualTo(30));
    }
    @Test void expiredWindowDoesNotAccumulateFailuresAndRetentionResetsProgression() {
        fail("a@example.test");fail("a@example.test");clock.advance(Duration.ofSeconds(60));fail("a@example.test");
        assertThat(store.states.get("a@example.test").failures()).isEqualTo(1);
        fail("a@example.test");fail("a@example.test");clock.advance(Duration.ofSeconds(600));
        for(int i=0;i<3;i++)fail("a@example.test");
        assertThatThrownBy(()->guard.execute("a@example.test",this::bad))
            .satisfies(e->assertThat(((LoginThrottledException)e).retryAfterSeconds()).isEqualTo(30));
    }
    @Test void infrastructureFailureDoesNotCountAsWrongCredentials() {
        fail("a@example.test");var state=store.states.get("a@example.test");
        assertThatThrownBy(()->guard.execute("a@example.test",()->{throw new IllegalStateException("adapter down");}))
            .isInstanceOf(IllegalStateException.class);
        assertThat(store.states.get("a@example.test")).isEqualTo(state);
    }
    @Test void failuresAcrossTheFirstWindowBoundaryStillCountInTheLastSixtySeconds() {
        fail("a@example.test");clock.advance(Duration.ofSeconds(59));fail("a@example.test");
        clock.advance(Duration.ofSeconds(2));fail("a@example.test");
        clock.advance(Duration.ofSeconds(1));fail("a@example.test");
        assertThatThrownBy(()->guard.execute("a@example.test",this::good)).isInstanceOf(LoginThrottledException.class);
    }
    static final class FakeStore implements LoginAttemptStore {
        final Map<String,State> states=new HashMap<>();
        public <T>T compute(String key,Function<State,Update<T>> action){
            Update<T> update=action.apply(states.get(key));
            if(update.state()==null)states.remove(key);else states.put(key,update.state());return update.result();
        }
        public void removeExpired(Instant cutoff){states.values().removeIf(s->!s.evaluatedAt().isAfter(cutoff));}
    }
    static final class MutableClock extends Clock {
        Instant now=Instant.parse("2026-11-15T12:00:00Z");
        void advance(Duration duration){now=now.plus(duration);}
        public Instant instant(){return now;}
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
    }
}
