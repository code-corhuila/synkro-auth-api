package co.edu.corhuila.synkro.auth.application.usecase;
import co.edu.corhuila.synkro.auth.application.port.out.*;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.function.Supplier;
import co.edu.corhuila.synkro.auth.domain.model.Emails;
import co.edu.corhuila.synkro.auth.application.port.out.LoginAttemptStore.*;

public final class AccountLoginProtection {
    private final LoginAttemptStore store;
    private final HashFunction hash;
    private final Clock clock;
    private final int threshold;
    private final long window,initial,cap,retention;
    public AccountLoginProtection(LoginAttemptStore store,HashFunction hash,Clock clock,int threshold,long window,long initial,long cap,long retention) {
        if(threshold<1 || threshold>100 || window<1 || initial<1 || cap<initial || cap>86400 || retention<Math.max(cap,window) || retention>604800)
            throw new IllegalArgumentException("Invalid account login policy");
        this.store=store;this.hash=hash;this.clock=clock;this.threshold=threshold;
        this.window=window;this.initial=initial;this.cap=cap;this.retention=retention;
    }
    public LoginResult execute(String email,Supplier<LoginResult> attempt) {
        Decision decision=store.compute(hash.hash(Emails.normalize(email)),previous->{
            Instant now=clock.instant();
            State state=previous;
            if(state!=null && !state.evaluatedAt().isAfter(now.minusSeconds(retention)))state=null;
            if(state!=null && state.blockedUntil().isAfter(now)) {
                Duration remaining=Duration.between(now,state.blockedUntil());
                long retry=remaining.getSeconds()+(remaining.getNano()>0?1:0);
                throw new LoginThrottledException(Math.max(1,retry));
            }
            try {return new Update<Decision>(null,new Decision(attempt.get(),null));}
            catch(InvalidCredentialsException failure) {
                return new Update<>(failed(state,clock.instant()),new Decision(null,failure));
            }
        });
        if(decision.failure()!=null)throw decision.failure();
        return decision.result();
    }
    private State failed(State state,Instant now) {
        var failures=new ArrayList<Instant>();
        if(state!=null)for(Instant failure:state.failuresAt())
            if(failure.isAfter(now.minusSeconds(window)))failures.add(failure);
        failures.add(now);
        int cycle=state==null?0:state.cycle();
        if(failures.size()<threshold)return new State(failures,cycle,Instant.MIN,now);
        long wait=initial;
        for(int i=0;i<cycle && wait<cap;i++)wait=wait>cap/2?cap:wait*2;
        return new State(java.util.List.of(),Math.min(31,cycle+1),now.plusSeconds(Math.min(wait,cap)),now);
    }
    private record Decision(LoginResult result,InvalidCredentialsException failure) {}
}
