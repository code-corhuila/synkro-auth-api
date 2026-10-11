package co.edu.corhuila.synkro.auth.app;

import co.edu.corhuila.synkro.auth.adapter.out.crypto.BcryptPasswordHasher;
import co.edu.corhuila.synkro.auth.adapter.out.persistence.jdbc.JdbcInitialAdminStore;
import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore;
import co.edu.corhuila.synkro.auth.application.usecase.BusinessRuleViolationException;
import co.edu.corhuila.synkro.auth.application.usecase.InitialAdminCommand;
import co.edu.corhuila.synkro.auth.application.usecase.InitialAdminResult;
import co.edu.corhuila.synkro.auth.application.usecase.InitializationFailedException;
import co.edu.corhuila.synkro.auth.application.usecase.InitializeAdminUseCase;
import co.edu.corhuila.synkro.auth.application.usecase.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * The operational command that creates the first administrator of an environment (HU-AUTH-14). It is composed by
 * hand, with no Spring context: it opens no HTTP listener, needs no application JWT and reads the same
 * SPRING_DATASOURCE_* variables as the service, which means it connects as auth_app and as nothing else.
 *
 * <pre>
 *   java -cp auth-app.jar -Dloader.main=co.edu.corhuila.synkro.auth.app.InitialAdminCli \
 *        org.springframework.boot.loader.launch.PropertiesLauncher --name … --email … --password-file …
 * </pre>
 *
 * Responsibilities: this class owns the protected input, the execution context (operator, correlation id), the
 * output and the exit code; {@link InitializeAdminUseCase} owns the rules; {@link JdbcInitialAdminStore} owns the
 * transaction. The command is authorized by the controlled deployment session that runs it, not by anything it
 * can check: the operator identity is attribution, not proof.
 */
public final class InitialAdminCli {

    /** Created, or an ADMIN already existed: both are a successful execution; the output tells them apart. */
    public static final int EXIT_SUCCESS = 0;
    /** An unexpected failure outside the categories below. */
    public static final int EXIT_UNEXPECTED = 1;
    /** Invalid arguments, input or configuration, or an email that already belongs to another user. */
    public static final int EXIT_INVALID = 2;
    /** The advisory lock was not obtained within ten seconds. Nothing was written. */
    public static final int EXIT_LOCK_TIMEOUT = 3;
    /** The database refused or lost the work before the commit. Nothing was kept. */
    public static final int EXIT_DATABASE = 4;
    /** The commit was sent but not confirmed: the administrator may or may not exist. */
    public static final int EXIT_UNCERTAIN = 5;

    static final String ENV_OPERATOR = "SYNKRO_INIT_OPERATOR";
    static final String ENV_CORRELATION_ID = "SYNKRO_INIT_CORRELATION_ID";
    static final String ENV_NAME = "SYNKRO_INIT_ADMIN_NAME";
    static final String ENV_EMAIL = "SYNKRO_INIT_ADMIN_EMAIL";
    static final String ENV_PASSWORD_FILE = "SYNKRO_INIT_ADMIN_PASSWORD_FILE";

    private static final String NO_REASON = "-";

    /** Reads a secret without echo. Returns null when no protected input is available. */
    @FunctionalInterface
    interface PasswordPrompt {
        char[] read(String label);
    }

    /** One line per execution that reached a decision, in the security log of the service. */
    @FunctionalInterface
    interface OutcomeLog {
        void record(String outcome, String operator, String reason, String correlationId);
    }

    private final Map<String, String> env;
    private final PasswordPrompt prompt;
    private final PrintStream out;
    private final PrintStream err;
    private final Function<DatasourceSettings, InitialAdminStore> stores;
    private final OutcomeLog log;

    InitialAdminCli(Map<String, String> env, PasswordPrompt prompt, PrintStream out, PrintStream err,
                    Function<DatasourceSettings, InitialAdminStore> stores, OutcomeLog log) {
        this.env = env;
        this.prompt = prompt;
        this.out = out;
        this.err = err;
        this.stores = stores;
        this.log = log;
    }

    public static void main(String[] args) {
        int exit = new InitialAdminCli(System.getenv(), consolePrompt(), System.out, System.err,
            InitialAdminCli::postgresStore, new Slf4jOutcomeLog()).run(args);
        System.exit(exit);
    }

    int run(String[] args) {
        String operator = null;
        String correlationId = generated();
        try {
            Options options = Options.parse(args);
            if (options.help) {
                out.print(USAGE);
                out.flush();
                return EXIT_SUCCESS;
            }
            operator = firstNonBlank(options.operator, env.get(ENV_OPERATOR));
            correlationId = firstNonBlank(options.correlationId, env.get(ENV_CORRELATION_ID), correlationId);

            DatasourceSettings settings = DatasourceSettings.resolve(env.get("SPRING_DATASOURCE_URL"),
                env.get("SPRING_DATASOURCE_USERNAME"), env.get("SPRING_DATASOURCE_PASSWORD"),
                env.get("SPRING_DATASOURCE_PASSWORD_FILE"));
            String name = firstNonBlank(options.name, env.get(ENV_NAME));
            String email = firstNonBlank(options.email, env.get(ENV_EMAIL));
            String password = readPassword(firstNonBlank(options.passwordFile, env.get(ENV_PASSWORD_FILE)));

            // The connection is opened only when the use case reaches the store, after the input is valid.
            InitialAdminStore lazyStore = (admin, audit) -> stores.apply(settings).initializeAdministrator(admin, audit);
            InitialAdminResult result = new InitializeAdminUseCase(lazyStore, new BcryptPasswordHasher(),
                () -> UUID.randomUUID().toString(), Clock.systemUTC())
                .execute(new InitialAdminCommand(name, email, password, operator, correlationId));
            return succeeded(result, operator, correlationId);
        } catch (UsageException | DatasourceConfigurationException e) {
            return rejected(e.getMessage(), "invalid-arguments", operator, correlationId);
        } catch (ValidationException e) {
            String fields = e.problems().stream().map(ValidationException.Problem::field).collect(Collectors.joining(","));
            e.problems().forEach(p -> err.println("error: " + p.message()));
            return rejected(null, fields, operator, correlationId);
        } catch (BusinessRuleViolationException e) {
            return rejected(e.getMessage(), e.field(), operator, correlationId);
        } catch (InitializationFailedException e) {
            return failed(e, operator, correlationId);
        } catch (RuntimeException e) {
            err.println("error: unexpected failure (" + e.getClass().getSimpleName() + "). correlationId=" + correlationId);
            log.record("FAILED", safeOperator(operator), e.getClass().getSimpleName(), correlationId);
            return EXIT_UNEXPECTED;
        } finally {
            out.flush();
            err.flush();
        }
    }

    private int succeeded(InitialAdminResult result, String operator, String correlationId) {
        if (result.created()) {
            out.println("result=created");
            out.println("userId=" + result.userId());
            out.println("correlationId=" + correlationId);
            log.record("CREATED", operator.strip(), NO_REASON, correlationId);
        } else {
            out.println("result=already_initialized");
            out.println("correlationId=" + correlationId);
            log.record("ALREADY_INITIALIZED", operator.strip(), NO_REASON, correlationId);
        }
        return EXIT_SUCCESS;
    }

    private int rejected(String message, String reason, String operator, String correlationId) {
        if (message != null) {
            err.println("error: " + message);
        }
        log.record("REJECTED", safeOperator(operator), reason, correlationId);
        return EXIT_INVALID;
    }

    private int failed(InitializationFailedException e, String operator, String correlationId) {
        int exit;
        switch (e.kind()) {
            case LOCK_TIMEOUT -> {
                err.println("error: the initialization lock was not obtained within 10 seconds (SQLSTATE " + e.sqlState()
                    + "). Nothing was written. Another initialization may be running, or a session holds the lock:"
                    + " inspect pg_locks and pg_stat_activity for advisory key 1398361682 before running the command again."
                    + " correlationId=" + correlationId);
                exit = EXIT_LOCK_TIMEOUT;
            }
            case DATABASE -> {
                err.println("error: the database failed during the initialization (SQLSTATE " + e.sqlState()
                    + "). Nothing was kept. Check the connection settings and the database, then run the command again."
                    + " correlationId=" + correlationId);
                exit = EXIT_DATABASE;
            }
            default -> {
                err.println("error: the outcome could not be confirmed (SQLSTATE " + e.sqlState()
                    + "). The administrator may or may not exist. Do not assume either: run the command again with"
                    + " the same settings; if the administrator was created it reports already_initialized."
                    + " correlationId=" + correlationId);
                exit = EXIT_UNCERTAIN;
            }
        }
        log.record(e.kind().name(), safeOperator(operator), e.sqlState(), correlationId);
        return exit;
    }

    // ── protected input ─────────────────────────────────────────────────────

    private String readPassword(String passwordFile) {
        if (passwordFile != null) {
            return readSecretFile(Path.of(passwordFile));
        }
        char[] first = prompt.read("Administrator password: ");
        if (first == null) {
            throw new UsageException("No protected input is available (there is no console), so the password cannot be"
                + " typed without echo. Provide it in a deployment-managed secret file with --password-file.");
        }
        char[] second = prompt.read("Repeat the password: ");
        try {
            if (second == null || !Arrays.equals(first, second)) {
                throw new UsageException("The passwords do not match");
            }
            return new String(first);
        } finally {
            Arrays.fill(first, '\0');
            if (second != null) {
                Arrays.fill(second, '\0');
            }
        }
    }

    // Only the line ending is removed: any other whitespace belongs to the password. The file is never deleted.
    private static String readSecretFile(Path file) {
        String content;
        try {
            content = Files.readString(file, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            throw new UsageException("The password file does not exist or is not readable");
        }
        String secret = content.replaceAll("[\\r\\n]+$", "");
        if (secret.isEmpty()) {
            throw new UsageException("The password file is empty");
        }
        return secret;
    }

    static PasswordPrompt consolePrompt() {
        Console console = System.console();
        return console == null ? label -> null : label -> console.readPassword("%s", label);
    }

    // ── wiring ──────────────────────────────────────────────────────────────

    // Its own connection, not the service's pool: no Spring context, and no 5 s statement timeout to cut the lock
    // wait short. The socket timeout only bounds a connection that has gone silent; a commit it interrupts is
    // reported as uncertain.
    static InitialAdminStore postgresStore(DatasourceSettings settings) {
        Properties properties = new Properties();
        properties.setProperty("user", settings.username());
        properties.setProperty("password", settings.password());
        properties.setProperty("ApplicationName", "synkro-auth-initial-admin");
        properties.setProperty("connectTimeout", "10");
        properties.setProperty("socketTimeout", "60");
        return new JdbcInitialAdminStore(() -> {
            try {
                Class.forName("org.postgresql.Driver");
            } catch (ClassNotFoundException e) {
                throw new SQLException("PostgreSQL driver is not on the classpath", "08001");
            }
            return DriverManager.getConnection(settings.url(), properties);
        });
    }

    private static final class Slf4jOutcomeLog implements OutcomeLog {
        private static final Logger LOG = LoggerFactory.getLogger("synkro.auth.initialization");

        @Override
        public void record(String outcome, String operator, String reason, String correlationId) {
            String line = "operation=INITIAL_ADMIN_CREATE outcome={} operator={} reason={} correlationId={} at={}";
            if ("CREATED".equals(outcome) || "ALREADY_INITIALIZED".equals(outcome)) {
                LOG.info(line, outcome, operator, reason, correlationId, Instant.now());
            } else {
                LOG.warn(line, outcome, operator, reason, correlationId, Instant.now());
            }
        }
    }

    // ── arguments ───────────────────────────────────────────────────────────

    private static final String USAGE = """
        Creates the first ADMIN of an environment, once, from a controlled deployment session.

        usage: InitialAdminCli --name <name> --email <email> [--password-file <file>]
                               [--operator <identity>] [--correlation-id <id>]

          --password-file  file holding only the password (deployment-managed secret). Without it the password is
                           read twice from the console without echo; with no console the command fails.
          --operator       deployment identity of whoever runs this (or SYNKRO_INIT_OPERATOR). Required.
          --correlation-id identifier shared by the output, the log and the audit record (default: generated).

        Also read from the environment: SYNKRO_INIT_ADMIN_NAME, SYNKRO_INIT_ADMIN_EMAIL,
        SYNKRO_INIT_ADMIN_PASSWORD_FILE, SPRING_DATASOURCE_URL, SPRING_DATASOURCE_USERNAME (auth_app) and one of
        SPRING_DATASOURCE_PASSWORD_FILE or SPRING_DATASOURCE_PASSWORD. A password is never accepted as an argument.

        exit codes: 0 created or already initialized (see the result= line) | 1 unexpected failure
                    2 invalid input or configuration | 3 lock timeout | 4 database failure | 5 outcome not confirmed
        """;

    private static final class UsageException extends RuntimeException {
        UsageException(String message) {
            super(message, null, false, false);
        }
    }

    private static final class Options {
        String name;
        String email;
        String passwordFile;
        String operator;
        String correlationId;
        boolean help;

        static Options parse(String[] args) {
            Options options = new Options();
            Map<String, String> values = new HashMap<>();
            for (int i = 0; i < args.length; i++) {
                String option = args[i];
                String key = option.split("=", 2)[0];
                if (key.equals("--help") || key.equals("-h")) {
                    options.help = true;
                    continue;
                }
                if (key.startsWith("--password") && !key.equals("--password-file")) {
                    throw new UsageException("A password is never accepted as an argument: use --password-file or the protected prompt");
                }
                if (!Arrays.asList("--name", "--email", "--password-file", "--operator", "--correlation-id").contains(key)
                    || option.contains("=")) {
                    // Only the option's name is repeated: the part after '=' could be a secret.
                    throw new UsageException("Unknown or malformed option " + key + " (values follow the option as a separate argument; see --help)");
                }
                if (i + 1 >= args.length) {
                    throw new UsageException("The option " + key + " needs a value");
                }
                values.put(key, args[++i]);
            }
            options.name = values.get("--name");
            options.email = values.get("--email");
            options.passwordFile = values.get("--password-file");
            options.operator = values.get("--operator");
            options.correlationId = values.get("--correlation-id");
            return options;
        }
    }

    // ── small helpers ───────────────────────────────────────────────────────

    private static String generated() {
        return UUID.randomUUID().toString();
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate;
            }
        }
        return null;
    }

    // An operator that failed validation is not copied into a log line.
    private static String safeOperator(String operator) {
        boolean usable = operator != null && !operator.isBlank() && operator.strip().length() <= 200
            && operator.chars().noneMatch(Character::isISOControl);
        return usable ? operator.strip() : NO_REASON;
    }
}
