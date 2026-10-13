package com.example.devsecopslab.security;

import java.util.Collection;
import java.util.List;
import com.example.devsecopslab.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class LabPrincipal implements UserDetails, CredentialsContainer {
    private final long id;
    private final String username;
    private String passwordHash;
    private final List<GrantedAuthority> authorities;

    public LabPrincipal(User user) {
        id = user.getId();
        username = user.getUsername();
        passwordHash = user.getPasswordHash();
        authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
    }

    public long getId() {
        return id;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public void eraseCredentials() {
        passwordHash = null;
    }
}
