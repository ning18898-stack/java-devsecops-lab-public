package com.example.devsecopslab.dto;

import java.time.LocalDateTime;
import com.example.devsecopslab.entity.Article;

public record ArticleResponse(Long id, Long userId, String title, String content,
                              LocalDateTime createdAt, LocalDateTime updatedAt) {
    public static ArticleResponse from(Article article) {
        return new ArticleResponse(article.getId(), article.getUserId(), article.getTitle(), article.getContent(),
                article.getCreatedAt(), article.getUpdatedAt());
    }
}
