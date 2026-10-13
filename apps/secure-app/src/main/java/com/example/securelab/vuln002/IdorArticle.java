package com.example.securelab.vuln002;
import java.time.LocalDateTime;
public record IdorArticle(long id, long userId, String title, String content,
        LocalDateTime createdAt, LocalDateTime updatedAt, String runId) { }
