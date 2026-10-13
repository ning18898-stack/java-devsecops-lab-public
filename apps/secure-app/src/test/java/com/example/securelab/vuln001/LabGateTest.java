package com.example.securelab.vuln001;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

class LabGateTest {
    @Test
    void featureRequiresBothProfileAndExplicitSwitch() {
        for (boolean profile : new boolean[] {false, true}) {
            for (boolean enabled : new boolean[] {false, true}) {
                if (profile && enabled) { continue; }
                new ApplicationContextRunner().withUserConfiguration(LabConfiguration.class, LabController.class)
                        .withInitializer(context -> context.getEnvironment().setActiveProfiles(profile ? "vuln001-local" : "local"))
                        .withPropertyValues("lab.vuln001.enabled=" + enabled)
                        .run(context -> {
                            assertThat(context).doesNotHaveBean(LabDatabase.class);
                            assertThat(context).doesNotHaveBean(LabController.class);
                        });
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"0.0.0.0", "::", "192.168.1.1", "localhost", ""})
    void rejectsNonExplicitLoopbackBindings(String address) {
        var environment = new MockEnvironment().withProperty("server.address", address);
        assertThatThrownBy(() -> LabGuard.verify(environment, LabGuard.MYSQL_URL, "vuln001_reader"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsOtherDatabasesRemoteHostsAndMultipleStatements() {
        var environment = new MockEnvironment().withProperty("server.address", "127.0.0.1");
        for (String url : new String[] {LabGuard.MYSQL_URL.replace("127.0.0.1", "example.com"),
                LabGuard.MYSQL_URL.replace("lab_vuln001", "lab"),
                LabGuard.MYSQL_URL.replace("allowMultiQueries=false", "allowMultiQueries=true"), LabGuard.H2_URL}) {
            assertThatThrownBy(() -> LabGuard.verify(environment, url, "vuln001_reader"))
                    .isInstanceOf(IllegalStateException.class);
        }
        assertThatThrownBy(() -> LabGuard.verify(environment, LabGuard.MYSQL_URL, "root"))
                .isInstanceOf(IllegalStateException.class);
        assertThat(LabGuard.verify(environment, LabGuard.MYSQL_URL, "vuln001_reader")).isFalse();
    }

    @Test
    void inMemoryFixtureIsAllowedOnlyInExplicitTestProfile() {
        var environment = new MockEnvironment().withProperty("server.address", "127.0.0.1");
        environment.setActiveProfiles("test", "vuln001-local");
        assertThat(LabGuard.verify(environment, LabGuard.H2_URL, "sa")).isTrue();
    }

    @Test
    void grantsAllowOnlyUsageAndSelectOnFixtureTable() {
        assertThat(LabGuard.allowedGrant("GRANT USAGE ON *.* TO `vuln001_reader`@`%`")).isTrue();
        assertThat(LabGuard.allowedGrant("GRANT SELECT ON `lab_vuln001`.`lab_articles` TO `vuln001_reader`@`%`")).isTrue();
        assertThat(LabGuard.allowedGrant("GRANT ALL PRIVILEGES ON `lab_vuln001`.* TO user")).isFalse();
        assertThat(LabGuard.allowedGrant("GRANT SELECT ON *.* TO user")).isFalse();
        assertThat(LabGuard.allowedGrant("GRANT SELECT ON lab_vuln001.lab_articles TO user WITH GRANT OPTION")).isFalse();
    }
}
