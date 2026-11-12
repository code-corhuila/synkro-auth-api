package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.CredentialIssuanceStore;
import co.edu.corhuila.synkro.auth.application.port.out.HashFunction;
import co.edu.corhuila.synkro.auth.application.port.out.PasswordHasher;
import co.edu.corhuila.synkro.auth.application.port.out.TokenIssuer;
import co.edu.corhuila.synkro.auth.application.port.out.UserRepository;
import co.edu.corhuila.synkro.auth.domain.model.Emails;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

public class LoginUseCase {
    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final TokenIssuer tokenIssuer;
    private final CredentialIssuanceStore issuance;
    private final HashFunction hashFunction;
    private final Clock clock;
    private final Duration refreshTokenTtl;
    // Verified when there is no usable user, so that every failed login costs one bcrypt verification
    // at the same cost factor and its response time says nothing about which emails exist.
    private final String standInHash;

    public LoginUseCase(UserRepository userRepository, PasswordHasher passwordHasher, TokenIssuer tokenIssuer,
                        CredentialIssuanceStore issuance, HashFunction hashFunction,
                        Clock clock, Duration refreshTokenTtl) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.tokenIssuer = tokenIssuer;
        this.issuance = issuance;
        this.hashFunction = hashFunction;
        this.clock = clock;
        this.refreshTokenTtl = refreshTokenTtl;
        this.standInHash = passwordHasher.hash(UUID.randomUUID().toString());
    }

    public LoginResult execute(String email, String password) {
        Optional<SystemUser> found = userRepository.findByEmail(Emails.normalize(email));

        // The verification runs whatever the outcome of the lookup; the decision comes after it.
        String hashToVerify = found.map(SystemUser::getPasswordHash).orElse(standInHash);
        boolean passwordMatches = passwordHasher.matches(password == null ? "" : password, hashToVerify);

        SystemUser user = found
            .filter(SystemUser::isActive)
            .filter(u -> password != null && passwordMatches)
            .orElseThrow(InvalidCredentialsException::new);

        // The bcrypt check above ran outside any lock. The credential is stored by one unit that takes the owner's lock,
        // reads the user as it is now and refuses if the stored hash is no longer the one verified (a reset committed in
        // between) or the user is no longer active. The same generic 401 answers every refusal. Nothing is returned
        // before the unit commits, and the claims come from the identity the unit read, not from the earlier lookup.
        String refreshToken = tokenIssuer.issueRefreshToken();
        SystemUser current = issuance.persistRefresh(user.getUserId(), user.getPasswordHash(), hashFunction.hash(refreshToken),
                clock.instant().plus(refreshTokenTtl))
            .orElseThrow(InvalidCredentialsException::new);
        String accessToken = tokenIssuer.issueAccessToken(current.getUserId(), current.getRole());

        return new LoginResult(accessToken, refreshToken);
    }
}
