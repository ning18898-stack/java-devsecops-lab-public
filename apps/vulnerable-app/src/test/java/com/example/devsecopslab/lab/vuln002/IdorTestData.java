package com.example.devsecopslab.lab.vuln002;
import java.sql.*;
import java.util.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
final class IdorTestData implements AutoCloseable {
    final String run = UUID.randomUUID().toString().replace("-", "");
    final String alice = "alice_" + run;
    final String bob = "bob_" + run;
    final String password = UUID.randomUUID().toString();
    final String schema = "lab_vuln002_vulnerable_test";
    final long aliceId;
    final long bobId;
    IdorTestData() throws Exception {
        String hash = new BCryptPasswordEncoder(12).encode(password);
        aliceId = insertUser(alice, hash);
        bobId = insertUser(bob, hash);
    }
    Connection connection(String role) throws Exception {
        return DriverManager.getConnection("jdbc:mysql://127.0.0.1:13309/" + schema
                + "?allowMultiQueries=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true",
                "v002_vulnerable_test_" + role, System.getenv("VULN002_" + role.toUpperCase(Locale.ROOT) + "_PASSWORD"));
    }
    private long insertUser(String name, String hash) throws Exception {
        try (var connection = connection("manager"); var statement = connection.prepareStatement(
                "INSERT INTO lab_users(run_id, username, password_hash, role) VALUES(?,?,?,'USER')", Statement.RETURN_GENERATED_KEYS)) {
            statement.setString(1, run); statement.setString(2, name); statement.setString(3, hash);
            statement.executeUpdate();
            try (var rows = statement.getGeneratedKeys()) { rows.next(); return rows.getLong(1); }
        }
    }
    long article(long owner, String title) throws Exception {
        try (var connection = connection("manager"); var statement = connection.prepareStatement(
                "INSERT INTO lab_articles(run_id,user_id,title,content) VALUES(?,?,?,'Initial synthetic content')", Statement.RETURN_GENERATED_KEYS)) {
            statement.setString(1,run); statement.setLong(2,owner); statement.setString(3,title);
            statement.executeUpdate();
            try (var rows = statement.getGeneratedKeys()) { rows.next(); return rows.getLong(1); }
        }
    }
    Map<String,Object> snapshot(long id) throws Exception {
        // New reader connection, never the request's connection or transaction.
        try (var connection = connection("reader"); var statement = connection.prepareStatement(
                "SELECT id,user_id,title,content,created_at,updated_at,run_id FROM lab_articles WHERE id=?")) {
            statement.setLong(1,id);
            try (var rows = statement.executeQuery()) {
                if (!rows.next()) { return Map.of(); }
                var result = new LinkedHashMap<String,Object>();
                for (int i=1;i<=7;i++) { result.put(rows.getMetaData().getColumnLabel(i),rows.getObject(i)); }
                return result;
            }
        }
    }
    @Override public void close() throws Exception {
        try (var connection = connection("manager")) {
            connection.setAutoCommit(false);
            for (String table : List.of("lab_articles","lab_users")) {
                try (var statement = connection.prepareStatement("DELETE FROM " + table + " WHERE run_id=?")) {
                    statement.setString(1,run); statement.executeUpdate();
                }
            }
            connection.commit();
        }
    }
}
