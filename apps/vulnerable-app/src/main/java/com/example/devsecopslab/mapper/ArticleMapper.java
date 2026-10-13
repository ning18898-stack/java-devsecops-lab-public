package com.example.devsecopslab.mapper;

import java.util.List;
import com.example.devsecopslab.entity.Article;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

public interface ArticleMapper {
    @Insert("INSERT INTO articles (user_id, title, content) VALUES (#{userId}, #{title}, #{content})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(Article article);

    @Select("SELECT id, user_id, title, content, created_at, updated_at FROM articles WHERE id = #{id}")
    Article findById(@Param("id") long id);

    @Select("SELECT id, user_id, title, content, created_at, updated_at FROM articles ORDER BY id DESC LIMIT #{limit} OFFSET #{offset}")
    List<Article> list(@Param("limit") int limit, @Param("offset") long offset);

    @Select("SELECT id, user_id, title, content, created_at, updated_at FROM articles WHERE title LIKE #{pattern} ESCAPE '!' OR content LIKE #{pattern} ESCAPE '!' ORDER BY id DESC LIMIT #{limit} OFFSET #{offset}")
    List<Article> search(@Param("pattern") String pattern, @Param("limit") int limit, @Param("offset") long offset);

    @Update("UPDATE articles SET title = #{title}, content = #{content}, updated_at = CURRENT_TIMESTAMP(6) WHERE id = #{id} AND user_id = #{ownerId}")
    int updateOwned(@Param("id") long id, @Param("ownerId") long ownerId,
                    @Param("title") String title, @Param("content") String content);

    @Delete("DELETE FROM articles WHERE id = #{id} AND user_id = #{ownerId}")
    int deleteOwned(@Param("id") long id, @Param("ownerId") long ownerId);
}
