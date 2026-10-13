package com.example.devsecopslab.lab.vuln001;

import java.util.Map;

public final class UnsafeSqlProvider {
    private UnsafeSqlProvider() { }

    public static String search(Map<String, Object> parameters) {
        // INTENTIONAL VULN-001: input becomes SQL syntax. Never use this in baseline APIs.
        return "SELECT id, title, visibility FROM lab_articles WHERE visibility = 'public' AND title = '"
                + parameters.get("query") + "' ORDER BY id LIMIT 10";
    }
}
