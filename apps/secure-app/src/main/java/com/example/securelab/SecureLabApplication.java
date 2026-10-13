package com.example.securelab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// The lab owns its pool and MyBatis factory; no general-purpose application database is configured here.
@SpringBootApplication(excludeName = {"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
        "org.mybatis.spring.boot.autoconfigure.MybatisAutoConfiguration"})
public class SecureLabApplication {
    public static void main(String[] args) { SpringApplication.run(SecureLabApplication.class, args); }
}
