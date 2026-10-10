package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.IdGenerator;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.UserRegistrationStore;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;

import java.time.Clock;

public class RegisterUserUseCase {

    public RegisterUserUseCase(UserRepository users, UserRegistrationStore registrations, PasswordHasher hasher,
                               IdGenerator ids, Clock clock) {
    }

    public RegisterUserResult execute(RegisterUserCommand command) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
