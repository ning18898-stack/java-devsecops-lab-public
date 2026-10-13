package com.example.devsecopslab.controller;

import java.util.List;
import com.example.devsecopslab.dto.ArticleRequest;
import com.example.devsecopslab.dto.ArticleResponse;
import com.example.devsecopslab.security.LabPrincipal;
import com.example.devsecopslab.service.ArticleService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/articles")
public class ArticleController {
    private final ArticleService articles;

    public ArticleController(ArticleService articles) {
        this.articles = articles;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    ArticleResponse create(@AuthenticationPrincipal LabPrincipal principal,
                           @Valid @RequestBody ArticleRequest request) {
        return articles.create(principal.getId(), request);
    }

    @GetMapping
    List<ArticleResponse> list(@RequestParam(defaultValue = "0") @Min(0) int page,
                               @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        return articles.list(page, size);
    }

    @GetMapping("/search")
    List<ArticleResponse> search(@RequestParam("q") @NotBlank @Size(max = 200) String query,
                                 @RequestParam(defaultValue = "0") @Min(0) int page,
                                 @RequestParam(defaultValue = "20") @Min(1) @Max(100) int size) {
        return articles.search(query, page, size);
    }

    @GetMapping("/{id}")
    ArticleResponse find(@PathVariable @Positive long id) {
        return articles.find(id);
    }

    @PutMapping("/{id}")
    ArticleResponse update(@PathVariable @Positive long id, @AuthenticationPrincipal LabPrincipal principal,
                           @Valid @RequestBody ArticleRequest request) {
        return articles.update(id, principal.getId(), request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(@PathVariable @Positive long id, @AuthenticationPrincipal LabPrincipal principal) {
        articles.delete(id, principal.getId());
    }
}
