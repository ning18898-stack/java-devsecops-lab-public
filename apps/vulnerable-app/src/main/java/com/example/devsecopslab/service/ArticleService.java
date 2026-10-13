package com.example.devsecopslab.service;

import java.util.List;
import com.example.devsecopslab.dto.ArticleRequest;
import com.example.devsecopslab.dto.ArticleResponse;
import com.example.devsecopslab.entity.Article;
import com.example.devsecopslab.exception.ApiException;
import com.example.devsecopslab.mapper.ArticleMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ArticleService {
    private final ArticleMapper articles;

    public ArticleService(ArticleMapper articles) {
        this.articles = articles;
    }

    @Transactional
    public ArticleResponse create(long ownerId, ArticleRequest request) {
        Article article = new Article();
        article.setUserId(ownerId);
        article.setTitle(request.title());
        article.setContent(request.content());
        articles.insert(article);
        return find(article.getId());
    }

    public ArticleResponse find(long id) {
        return ArticleResponse.from(requireArticle(id));
    }

    public List<ArticleResponse> list(int page, int size) {
        return articles.list(size, (long) page * size).stream().map(ArticleResponse::from).toList();
    }

    public List<ArticleResponse> search(String query, int page, int size) {
        // Treat LIKE wildcards as literal input; every value remains a bound parameter.
        String pattern = "%" + query.replace("!", "!!").replace("%", "!%")
                .replace("_", "!_") + "%";
        return articles.search(pattern, size, (long) page * size).stream().map(ArticleResponse::from).toList();
    }

    @Transactional
    public ArticleResponse update(long id, long ownerId, ArticleRequest request) {
        requireOwner(id, ownerId);
        if (articles.updateOwned(id, ownerId, request.title(), request.content()) == 0) {
            throw missing();
        }
        return find(id);
    }

    @Transactional
    public void delete(long id, long ownerId) {
        requireOwner(id, ownerId);
        if (articles.deleteOwned(id, ownerId) == 0) {
            throw missing();
        }
    }

    private Article requireArticle(long id) {
        Article article = articles.findById(id);
        if (article == null) {
            throw missing();
        }
        return article;
    }

    private void requireOwner(long id, long ownerId) {
        if (requireArticle(id).getUserId() != ownerId) {
            throw new ApiException(HttpStatus.FORBIDDEN, "Access denied");
        }
    }

    private ApiException missing() {
        return new ApiException(HttpStatus.NOT_FOUND, "Article not found");
    }
}
