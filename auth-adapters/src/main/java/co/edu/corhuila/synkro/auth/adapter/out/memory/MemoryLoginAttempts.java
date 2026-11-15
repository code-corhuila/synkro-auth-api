package co.edu.corhuila.synkro.auth.adapter.out.memory;

import co.edu.corhuila.synkro.auth.application.port.out.LoginAttemptStore;
import co.edu.corhuila.synkro.auth.application.usecase.LoginThrottledException;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

/** Process-local, bounded state. ConcurrentHashMap.compute serializes each account's complete evaluation. */
public final class MemoryLoginAttempts implements LoginAttemptStore {
    private final ConcurrentHashMap<String,State> accounts=new ConcurrentHashMap<>();
    private final Semaphore freeEntries;
    public MemoryLoginAttempts(int capacity) {
        if(capacity<1)throw new IllegalArgumentException("Account capacity must be positive");
        freeEntries=new Semaphore(capacity);
    }
    public <T>T compute(String key,Function<State,Update<T>> action) {
        var result=new AtomicReference<T>();
        accounts.compute(key,(ignored,state)->{
            boolean created=state==null;
            if(created && !freeEntries.tryAcquire())throw new LoginThrottledException(1);
            try {
                Update<T> update=action.apply(state);
                if(update.state()==null)freeEntries.release();
                result.set(update.result());
                return update.state();
            } catch(RuntimeException|Error failure) {
                if(created)freeEntries.release();
                throw failure;
            }
        });
        return result.get();
    }
    public void removeExpired(Instant cutoff) {
        accounts.forEach((key,ignored)->accounts.computeIfPresent(key,(k,current)->{
            if(current.evaluatedAt().isAfter(cutoff))return current;
            freeEntries.release();return null;
        }));
    }
    public int retainedAccounts(){return accounts.size();}
}
