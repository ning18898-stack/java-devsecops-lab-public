package com.example.devsecopslab.lab.vuln001;

import org.springframework.core.env.Environment;

public final class LabGuard {
    public static final String MYSQL_URL = "jdbc:mysql://127.0.0.1:13308/lab_vuln001?allowMultiQueries=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
    public static final String H2_URL = "jdbc:h2:mem:vuln001;MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1";

    private LabGuard() { }

    public static boolean verify(Environment environment, String url, String username) {
        if (!"127.0.0.1".equals(environment.getProperty("server.address"))) {
            throw new IllegalStateException("VULN-001 requires explicit loopback binding");
        }
        boolean test = environment.matchesProfiles("test") && H2_URL.equals(url) && "sa".equals(username);
        if (!test && !(MYSQL_URL.equals(url) && "vuln001_reader".equals(username))) {
            throw new IllegalStateException("VULN-001 requires the isolated local read-only database");
        }
        return test;
    }

    public static boolean allowedGrant(String grant) {
        String normalized = grant.replace("`", "").toUpperCase(java.util.Locale.ROOT);
        return !normalized.contains("WITH GRANT OPTION") && (normalized.startsWith("GRANT USAGE ON *.* TO ")
                || normalized.startsWith("GRANT SELECT ON LAB_VULN001.LAB_ARTICLES TO "));
    }
}
