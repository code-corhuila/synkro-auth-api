package co.edu.corhuila.synkro.auth.application.usecase;

import co.edu.corhuila.synkro.auth.application.port.out.InitialAdminStore;
import co.edu.corhuila.synkro.auth.domain.model.SystemUser;

/** Honours the contract of the port in memory: the first call creates, any later call is a no-op. */
class FakeInitialAdminStore implements InitialAdminStore {

    SystemUser savedAdmin;
    InitializationAudit savedAudit;
    int calls;
    /** When set, a call fails with it and keeps nothing, like a rolled-back transaction. */
    RuntimeException failure;

    @Override
    public InitialAdminResult initializeAdministrator(SystemUser admin, InitializationAudit audit) {
        calls++;
        if (failure != null) {
            throw failure;
        }
        if (savedAdmin != null) {
            return new InitialAdminResult(false, null);
        }
        savedAdmin = admin;
        savedAudit = audit;
        return new InitialAdminResult(true, admin.getUserId());
    }
}
