package com.example.devsecopslab.lab.vuln001;

import java.util.List;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;

public interface LabArticleMapper {
    @SelectProvider(type = UnsafeSqlProvider.class, method = "search")
    @Options(timeout = 3, useCache = false)
    List<LabArticle> search(@Param("query") String query);
}
