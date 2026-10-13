package com.example.devsecopslab.controller;

import com.example.devsecopslab.dto.UpdateUserRequest;
import com.example.devsecopslab.dto.UserResponse;
import com.example.devsecopslab.security.LabPrincipal;
import com.example.devsecopslab.service.UserService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users/me")
public class UserController {
    private final UserService users;

    public UserController(UserService users) {
        this.users = users;
    }

    @GetMapping
    UserResponse current(@AuthenticationPrincipal LabPrincipal principal) {
        return users.current(principal.getId());
    }

    @PutMapping
    UserResponse update(@AuthenticationPrincipal LabPrincipal principal,
                        @Valid @RequestBody UpdateUserRequest request) {
        return users.update(principal.getId(), request);
    }
}
