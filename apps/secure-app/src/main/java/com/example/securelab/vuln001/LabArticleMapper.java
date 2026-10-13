package com.example.securelab.vuln001;

import java.util.List;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface LabArticleMapper {
    @Select("SELECT id, title, visibility FROM lab_articles WHERE visibility = 'public' AND title = #{query} ORDER BY id LIMIT 10")
    @Options(timeout = 3, useCache = false)
    List<LabArticle> search(@Param("query") String query);
}
