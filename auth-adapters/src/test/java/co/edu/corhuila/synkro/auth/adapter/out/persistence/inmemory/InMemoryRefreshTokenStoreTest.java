package co.edu.corhuila.synkro.auth.adapter.out.persistence.inmemory;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryRefreshTokenStoreTest {

    private static final Instant LATER = Instant.parse("2999-01-01T00:00:00Z");

    private final InMemoryRefreshTokenStore store = new InMemoryRefreshTokenStore();

    @Test
    void consume_returnsTheOwnerOfASavedToken() {
        store.save("hash-1", "user-1", LATER);

        assertThat(store.consumeAndRotate("hash-1")).contains("user-1");
    }

    @Test
    void consume_isOneTimeUse() {
        store.save("hash-1", "user-1", LATER);
        store.consumeAndRotate("hash-1");

        assertThat(store.consumeAndRotate("hash-1")).isEmpty();
    }

    @Test
    void consume_ofAnUnknownTokenIsEmpty() {
        assertThat(store.consumeAndRotate("never-saved")).isEmpty();
    }

    @Test
    void consumingOneToken_leavesOthersUntouched() {
        store.save("hash-1", "user-1", LATER);
        store.save("hash-2", "user-2", LATER);
        store.consumeAndRotate("hash-1");

        assertThat(store.consumeAndRotate("hash-2")).contains("user-2");
    }

    @Test
    void whenManyThreadsReplayTheSameToken_exactlyOneWins() throws Exception {
        store.save("hash-1", "user-1", LATER);
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Optional<String>>> results = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            results.add(pool.submit(() -> {
                start.await();
                return store.consumeAndRotate("hash-1");
            }));
        }
        start.countDown();

        long winners = 0;
        for (Future<Optional<String>> f : results) {
            if (f.get().isPresent()) winners++;
        }
        pool.shutdown();

        assertThat(winners).isEqualTo(1);
    }
}
