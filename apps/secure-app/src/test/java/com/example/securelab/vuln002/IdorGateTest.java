package com.example.securelab.vuln002;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;
class IdorGateTest {
    @Test void profileAndSwitchBothRequired() {
        for(boolean profile:new boolean[]{false,true}) for(boolean enabled:new boolean[]{false,true}) {
            if(profile && enabled) continue;
            new ApplicationContextRunner().withUserConfiguration(IdorConfiguration.class,IdorSecurity.class,IdorAuthController.class)
                .withInitializer(c -> c.getEnvironment().setActiveProfiles(profile?"vuln002-local":"local"))
                .withPropertyValues("lab.vuln002.enabled="+enabled).run(c -> {
                    assertThat(c).doesNotHaveBean(IdorDatabase.class);
                    assertThat(c).doesNotHaveBean(IdorSecurity.class);
                    assertThat(c).doesNotHaveBean(IdorAuthController.class);
                });
        }
    }
    @Test void rejectsUnexpectedBindingSchemaAndUrlBeforeConnecting() {
        for(String address:java.util.List.of("0.0.0.0","localhost","::")) {
            assertThatThrownBy(() -> new IdorDatabase(new MockEnvironment().withProperty("server.address",address)))
                .isInstanceOf(IllegalStateException.class);
        }
        for(String schema:java.util.List.of("lab","lab_test","lab_vuln001","lab_vuln002_secure_test")) {
            assertThatThrownBy(() -> new IdorDatabase(new MockEnvironment().withProperty("server.address","127.0.0.1")
                .withProperty("lab.vuln002.schema",schema))).isInstanceOf(IllegalStateException.class);
        }
        assertThatThrownBy(() -> new IdorDatabase(new MockEnvironment().withProperty("server.address","127.0.0.1")
            .withProperty("lab.vuln002.url","jdbc:mysql://example.com/lab"))).isInstanceOf(IllegalStateException.class);
    }
}
