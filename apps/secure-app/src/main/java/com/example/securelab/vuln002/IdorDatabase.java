package com.example.securelab.vuln002;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.ibatis.session.Configuration;
import org.apache.ibatis.session.SqlSessionFactory;
import org.apache.ibatis.session.SqlSessionFactoryBuilder;
import org.apache.ibatis.transaction.jdbc.JdbcTransactionFactory;
import org.springframework.core.env.Environment;
public final class IdorDatabase implements AutoCloseable {
    private final HikariDataSource pool;
    private final SqlSessionFactory sessions;
    public IdorDatabase(Environment env) {
        String schema = env.getProperty("lab.vuln002.schema", "lab_vuln002_secure");
        boolean test = env.matchesProfiles("test", "mysql-test");
        if (!"127.0.0.1".equals(env.getProperty("server.address"))
                || !(schema.equals("lab_vuln002_secure") || test && schema.equals("lab_vuln002_secure_test"))) {
            throw new IllegalStateException("VULN-002 requires dedicated loopback database");
        }
        String suffix = schema.substring("lab_vuln002_".length());
        String url = "jdbc:mysql://127.0.0.1:13309/" + schema + "?allowMultiQueries=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
        String configured = env.getProperty("lab.vuln002.url", url);
        if (!url.equals(configured)) { throw new IllegalStateException("Unexpected VULN-002 URL"); }
        HikariConfig settings = new HikariConfig();
        settings.setJdbcUrl(url);
        settings.setUsername("v002_" + suffix + "_app");
        settings.setPassword(env.getRequiredProperty("VULN002_APP_PASSWORD"));
        settings.setMaximumPoolSize(3);
        settings.setConnectionTimeout(5000);
        settings.setPoolName("VULN002-secure");
        pool = new HikariDataSource(settings);
        try (var connection = pool.getConnection(); var statement = connection.createStatement()) {
            if (!"MySQL".equals(connection.getMetaData().getDatabaseProductName())
                    || !connection.getMetaData().getDatabaseProductVersion().startsWith("8.4.")
                    || !schema.equals(connection.getCatalog())) { throw new IllegalStateException(); }
            try (var rows = statement.executeQuery("SELECT lab_id FROM lab_identity")) {
                if (!rows.next() || !"VULN-002".equals(rows.getString(1)) || rows.next()) { throw new IllegalStateException(); }
            }
            java.util.Set<String> actual = new java.util.HashSet<>();
            try (var rows = statement.executeQuery("SHOW GRANTS FOR CURRENT_USER()")) {
                while (rows.next()) {
                    String grant = rows.getString(1).replace("`", "");
                    if (grant.contains("WITH GRANT OPTION")) { throw new IllegalStateException(); }
                    actual.add(grant.substring(0, grant.indexOf(" TO ")));
                }
            }
            if (!actual.equals(java.util.Set.of("GRANT USAGE ON *.*", "GRANT SELECT ON " + schema + ".lab_identity",
                    "GRANT SELECT ON " + schema + ".lab_users",
                    "GRANT SELECT, UPDATE (content, title, updated_at) ON " + schema + ".lab_articles"))) { throw new IllegalStateException(); }
        } catch (Exception error) {
            pool.close();
            throw new IllegalStateException("VULN-002 database identity or privileges rejected");
        }
        Configuration configuration = new Configuration(new org.apache.ibatis.mapping.Environment(
                "vuln002", new JdbcTransactionFactory(), pool));
        configuration.setDefaultStatementTimeout(3);
        configuration.addMapper(IdorMapper.class);
        sessions = new SqlSessionFactoryBuilder().build(configuration);
    }
    public IdorUser user(String name) {
        try (var session = sessions.openSession()) { return session.getMapper(IdorMapper.class).user(name); }
    }
    public org.apache.ibatis.session.SqlSession openTransaction() { return sessions.openSession(false); }
    public Configuration configuration() { return sessions.getConfiguration(); }
    @Override public void close() { pool.close(); }
}
