package com.example.devsecopslab.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_]{3,32}") String username,
        @NotBlank @Email @Size(max = 254) String email) {
}
