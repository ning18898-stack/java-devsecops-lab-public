package com.example.devsecopslab.service;

import java.util.Locale;
import com.example.devsecopslab.dto.RegisterRequest;
import com.example.devsecopslab.dto.UpdateUserRequest;
import com.example.devsecopslab.dto.UserResponse;
import com.example.devsecopslab.entity.Role;
import com.example.devsecopslab.entity.User;
import com.example.devsecopslab.exception.ApiException;
import com.example.devsecopslab.mapper.UserMapper;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserMapper users;
    private final PasswordEncoder passwords;

    public UserService(UserMapper users, PasswordEncoder passwords) {
        this.users = users;
        this.passwords = passwords;
    }

    @Transactional
    public UserResponse register(RegisterRequest request) {
        User user = new User();
        user.setUsername(request.username().toLowerCase(Locale.ROOT));
        user.setEmail(request.email().toLowerCase(Locale.ROOT));
        user.setPasswordHash(passwords.encode(request.password()));
        user.setRole(Role.USER);
        try {
            users.insert(user);
        } catch (DuplicateKeyException exception) {
            throw conflict();
        }
        return current(user.getId());
    }

    public UserResponse current(long userId) {
        User user = users.findById(userId);
        if (user == null) {
            throw new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }
        return UserResponse.from(user);
    }

    @Transactional
    public UserResponse update(long userId, UpdateUserRequest request) {
        try {
            if (users.updateProfile(userId, request.username().toLowerCase(Locale.ROOT),
                    request.email().toLowerCase(Locale.ROOT)) == 0) {
                throw new ApiException(HttpStatus.UNAUTHORIZED, "Authentication required");
            }
        } catch (DuplicateKeyException exception) {
            throw conflict();
        }
        return current(userId);
    }

    private ApiException conflict() {
        return new ApiException(HttpStatus.CONFLICT, "Username or email already exists");
    }
}
