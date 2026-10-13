package com.example.devsecopslab.dto;

import java.time.LocalDateTime;
import com.example.devsecopslab.entity.Role;
import com.example.devsecopslab.entity.User;

public record UserResponse(Long id, String username, Role role, String email,
                           LocalDateTime createdAt, LocalDateTime updatedAt) {
    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getRole(), user.getEmail(),
                user.getCreatedAt(), user.getUpdatedAt());
    }
}
