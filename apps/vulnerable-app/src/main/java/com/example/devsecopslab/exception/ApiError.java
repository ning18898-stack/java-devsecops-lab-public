package com.example.devsecopslab.exception;

import java.time.Instant;
import org.springframework.http.HttpStatus;

public record ApiError(String timestamp, int status, String error, String message, String path) {
    public static ApiError of(HttpStatus status, String message, String path) {
        return new ApiError(Instant.now().toString(), status.value(), status.getReasonPhrase(), message, path);
    }
}
