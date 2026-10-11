package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.ServiceTokenStore;
import co.edu.corhuila.synkro.auth.domain.model.ServiceToken;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/** Honours the contract of the port in memory: one token per key. */
class FakeServiceTokenStore implements ServiceTokenStore {

    final Map<String, ServiceToken> byKey = new LinkedHashMap<>();
    int issueCalls;
    RuntimeException failure;

    @Override
    public Optional<ServiceToken> findByIdempotencyKey(String idempotencyKey) {
        return Optional.ofNullable(byKey.get(idempotencyKey));
    }

    @Override
    public Issued issueOnce(String idempotencyKey, ServiceToken token) {
        issueCalls++;
        if (failure != null) {
            throw failure;
        }
        ServiceToken original = byKey.get(idempotencyKey);
        if (original != null) {
            return new Issued(original, false);
        }
        byKey.put(idempotencyKey, token);
        return new Issued(token, true);
    }
}
