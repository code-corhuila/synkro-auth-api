package co.edu.corhuila.synkro.auth.app;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** GET /health: public; checks only the service's own dependency, the auth_schema connection (cross-cutting.md section 4). */
@RestController
public class HealthController {

    private final DatabaseHealthProbe database;

    public HealthController(DatabaseHealthProbe database) {
        this.database = database;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        boolean databaseUp = database.isReachable();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", databaseUp ? "ok" : "degraded");
        body.put("service", "synkro-auth-api");
        body.put("timestamp", Instant.now().toString());
        body.put("dependencies", Map.of("database", databaseUp ? "ok" : "down"));
        return ResponseEntity.status(databaseUp ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }
}
