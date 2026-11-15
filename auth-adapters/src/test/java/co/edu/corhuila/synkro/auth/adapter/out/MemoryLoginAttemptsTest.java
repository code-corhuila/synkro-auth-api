package co.edu.corhuila.synkro.auth.adapter.out;

import co.edu.corhuila.synkro.auth.adapter.out.memory.MemoryLoginAttempts;
import co.edu.corhuila.synkro.auth.application.port.out.LoginAttemptStore.*;
import co.edu.corhuila.synkro.auth.application.usecase.LoginThrottledException;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.concurrent.*;
import java.util.ArrayList;
import static org.assertj.core.api.Assertions.*;

class MemoryLoginAttemptsTest {
    final Instant now=Instant.parse("2026-11-15T12:00:00Z");
    State state(int failures){return new State(java.util.Collections.nCopies(failures,now),0,now,now);}
    @Test void serializesConcurrentUpdatesToTheSameAccount() throws Exception {
        var store=new MemoryLoginAttempts(4);
        try(var pool=Executors.newFixedThreadPool(8)) {
            var results=new ArrayList<Future<Integer>>();
            for(int i=0;i<100;i++)results.add(pool.submit(()->store.compute("same",s->{int n=s==null?1:s.failures()+1;return new Update<>(state(n),n);} )));
            for(var result:results)result.get(10,TimeUnit.SECONDS);
            assertThat(store.<Integer>compute("same",s->new Update<>(s,s.failures()))).isEqualTo(100);
        }
    }
    @Test void capacityIsBoundedAndExceptionsOrExpiryDoNotLeakCapacity() {
        var store=new MemoryLoginAttempts(1);
        assertThatThrownBy(()->store.compute("one",s->{throw new IllegalStateException("adapter error");})).isInstanceOf(IllegalStateException.class);
        store.compute("one",s->new Update<>(state(1),null));
        assertThatThrownBy(()->store.compute("two",s->new Update<>(state(1),null))).isInstanceOf(LoginThrottledException.class);
        store.removeExpired(now.minusSeconds(1));
        assertThatThrownBy(()->store.compute("two",s->new Update<>(state(1),null))).isInstanceOf(LoginThrottledException.class);
        store.removeExpired(now);
        assertThat(store.retainedAccounts()).isZero();
        store.compute("two",s->new Update<>(state(1),null));
        store.compute("two",s->new Update<>(null,null));
        store.compute("three",s->new Update<>(state(1),null));
        assertThat(store.retainedAccounts()).isEqualTo(1);
    }
    @Test void cleanupCannotDropAnUpdatedOperationOrResetItsBudget() throws Exception {
        var store=new MemoryLoginAttempts(1);
        store.compute("one",s->new Update<>(state(2),null));
        var entered=new CountDownLatch(1);var release=new CountDownLatch(1);
        try(var pool=Executors.newFixedThreadPool(2)) {
            var update=pool.submit(()->store.compute("one",s->{
                entered.countDown();try{if(!release.await(5,TimeUnit.SECONDS))throw new IllegalStateException("barrier");}
                catch(InterruptedException e){throw new IllegalStateException(e);}
                return new Update<>(new State(java.util.List.of(now,now,now),1,now.plusSeconds(30),now.plusSeconds(1)),null);
            }));
            assertThat(entered.await(5,TimeUnit.SECONDS)).isTrue();
            var cleanup=pool.submit(()->store.removeExpired(now));
            release.countDown();update.get(5,TimeUnit.SECONDS);cleanup.get(5,TimeUnit.SECONDS);
            assertThat(store.<Integer>compute("one",s->new Update<>(s,s.failures()))).isEqualTo(3);
        } finally {release.countDown();}
    }
    @Test void rejectsInvalidCapacity(){assertThatIllegalArgumentException().isThrownBy(()->new MemoryLoginAttempts(0));}
    @Test void differentAccountsWithCollidingHashCodesCanVerifyConcurrently() throws Exception {
        var store=new MemoryLoginAttempts(2);
        var entered=new CountDownLatch(2);var release=new CountDownLatch(1);
        try(var pool=Executors.newFixedThreadPool(2)) {
            var tasks=new ArrayList<Future<?>>();
            for(String key:java.util.List.of("Aa","BB"))tasks.add(pool.submit(()->store.compute(key,s->{
                entered.countDown();
                try{if(!release.await(5,TimeUnit.SECONDS))throw new IllegalStateException("barrier");}
                catch(InterruptedException e){throw new IllegalStateException(e);}
                return new Update<>(state(1),null);
            })));
            try {assertThat(entered.await(1,TimeUnit.SECONDS)).isTrue();}
            finally {release.countDown();}
            for(var task:tasks)task.get(5,TimeUnit.SECONDS);
        }
    }
}
