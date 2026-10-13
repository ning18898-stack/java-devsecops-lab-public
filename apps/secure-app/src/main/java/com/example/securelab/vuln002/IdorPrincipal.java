package com.example.securelab.vuln002;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
public final class IdorPrincipal extends User {
    private final long id;
    private final String runId;
    public IdorPrincipal(IdorUser user) {
        super(user.username(), user.passwordHash(), List.of(new SimpleGrantedAuthority("ROLE_USER")));
        id = user.id();
        runId = user.runId();
    }
    public String getRunId() { return runId; }
    public long getId() { return id; }
}
