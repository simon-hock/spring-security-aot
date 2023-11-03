package be.oniryx.springsecurityaot;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest
class SpringSecurityAotApplicationTests {


    @DynamicPropertySource
    static void setOauth2Properties(DynamicPropertyRegistry dynamicPropertyRegistry) {
        dynamicPropertyRegistry.add("spring.security.oauth2.client.registration.microsoft.client-id", () -> "AZE");
        dynamicPropertyRegistry.add("spring.security.oauth2.client.registration.microsoft.client-secret", () -> "AZE");
        dynamicPropertyRegistry.add("azure-tenant", () -> "48041231-a485-46dd-8515-510fda1400a1");

    }

    @Test
    void contextLoads() {
    }

}
