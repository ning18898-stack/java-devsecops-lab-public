package com.example.devsecopslab.lab.vuln001;

import java.util.List;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

public final class LabDatabase implements AutoCloseable {
    private final HikariDataSource pool;
    private final SqlSessionFactory sessions;

    public LabDatabase(String url, String username, String password, boolean inMemoryTest) {
        HikariConfig settings = new HikariConfig();
        settings.setJdbcUrl(url);
        settings.setUsername(username);
        settings.setPassword(password);
        settings.setReadOnly(true);
        settings.setMaximumPoolSize(2);
        settings.setConnectionTimeout(5000);
        settings.setPoolName("VULN001-readonly");
        pool = new HikariDataSource(settings);
        try {
            if (inMemoryTest) {
                new ResourceDatabasePopulator(new ClassPathResource("db/001-vuln001-fixtures.sql")).execute(pool);
            }
            try (var connection = pool.getConnection()) {
                if (!inMemoryTest) {
                    var metadata = connection.getMetaData();
                    if (!"MySQL".equals(metadata.getDatabaseProductName())
                            || !metadata.getDatabaseProductVersion().startsWith("8.4.")
                            || !"lab_vuln001".equals(connection.getCatalog())) {
                        throw new IllegalStateException("Unexpected VULN-001 database identity");
                    }
                    try (var statement = connection.createStatement();
                         var grants = statement.executeQuery("SHOW GRANTS FOR CURRENT_USER()")) {
                        while (grants.next()) {
                            if (!LabGuard.allowedGrant(grants.getString(1))) {
                                throw new IllegalStateException("VULN-001 account has excess privileges");
                            }
                        }
                    }
                }
            }
            Configuration configuration = new Configuration(new org.apache.ibatis.mapping.Environment(
                    "vuln001-readonly", new JdbcTransactionFactory(), pool));
            configuration.addMapper(LabArticleMapper.class);
            sessions = new SqlSessionFactoryBuilder().build(configuration);
        } catch (Exception error) {
            pool.close();
            // Keep database/credential details out of the startup error message.
            throw new IllegalStateException("VULN-001 isolated database validation failed");
        }
    }

    public List<LabArticle> search(String query) {
        try (var session = sessions.openSession(true)) {
            return session.getMapper(LabArticleMapper.class).search(query);
        }
    }

    public Configuration configuration() { return sessions.getConfiguration(); }

    @Override
    public void close() { pool.close(); }
}
