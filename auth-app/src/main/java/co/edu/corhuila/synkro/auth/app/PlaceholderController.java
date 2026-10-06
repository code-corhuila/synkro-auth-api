package co.edu.corhuila.synkro.auth.app;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class PlaceholderController {

    @GetMapping("/users/{id}")
    public ResponseEntity<Void> placeholder() {
        return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).build();
    }
}
