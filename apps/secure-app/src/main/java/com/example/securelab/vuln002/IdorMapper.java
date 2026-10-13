package com.example.securelab.vuln002;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
public interface IdorMapper {
    @Select("SELECT id, username, password_hash AS passwordHash, run_id AS runId FROM lab_users WHERE username = #{name}")
    IdorUser user(@Param("name") String name);
    @Select("SELECT id,user_id AS userId,title,content,created_at AS createdAt,updated_at AS updatedAt,run_id AS runId FROM lab_articles WHERE id=#{id} AND run_id=#{runId}")
    IdorArticle find(@Param("id") long id, @Param("runId") String runId);
    @Update("UPDATE lab_articles SET title=#{title},content=#{content},updated_at=CURRENT_TIMESTAMP(6) WHERE id=#{id} AND run_id=#{runId} AND user_id=#{currentUserId}")
    int update(@Param("id") long id,@Param("runId") String runId,@Param("currentUserId") long currentUserId,
            @Param("title") String title,@Param("content") String content);
}
