package cz.ami.cas.config;

import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import org.apereo.cas.util.serialization.ComponentSerializationPlanConfigurer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ScopedProxyMode;

@EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
@Configuration(value = "InalogyAuthenticatorAuthenticationComponentSerializationConfiguration", proxyBeanMethods = false)
class InalogyAuthenticatorAuthenticationComponentSerializationConfiguration {
    @Bean
    @ConditionalOnMissingBean(name = "inalogyComponentSerializationPlanConfigurer")
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public ComponentSerializationPlanConfigurer inalogyComponentSerializationPlanConfigurer() {
        return plan -> plan.registerSerializableClass(InalogyAuthenticatorTokenCredential.class);
    }
}
