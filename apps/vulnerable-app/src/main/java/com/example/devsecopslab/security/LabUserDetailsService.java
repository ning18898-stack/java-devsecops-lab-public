package com.example.devsecopslab.security;

import java.util.Locale;
import com.example.devsecopslab.entity.User;
import com.example.devsecopslab.mapper.UserMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class LabUserDetailsService implements UserDetailsService {
    private final UserMapper users;

    public LabUserDetailsService(UserMapper users) {
        this.users = users;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = users.findByUsername(username.toLowerCase(Locale.ROOT));
        if (user == null) {
            throw new UsernameNotFoundException("Invalid credentials");
        }
        return new LabPrincipal(user);
    }
}
