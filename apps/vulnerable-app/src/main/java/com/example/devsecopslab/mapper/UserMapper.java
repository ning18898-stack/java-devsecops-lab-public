package com.example.devsecopslab.mapper;

import com.example.devsecopslab.entity.User;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

public interface UserMapper {
    @Select("SELECT id, username, password_hash, role, email, created_at, updated_at FROM app_users WHERE id = #{id}")
    User findById(@Param("id") long id);

    @Select("SELECT id, username, password_hash, role, email, created_at, updated_at FROM app_users WHERE username = #{username}")
    User findByUsername(@Param("username") String username);

    @Insert("INSERT INTO app_users (username, password_hash, role, email) VALUES (#{username}, #{passwordHash}, #{role}, #{email})")
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insert(User user);

    @Update("UPDATE app_users SET username = #{username}, email = #{email}, updated_at = CURRENT_TIMESTAMP(6) WHERE id = #{id}")
    int updateProfile(@Param("id") long id, @Param("username") String username, @Param("email") String email);
}
