package cz.ami.cas.config;

import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.controller.InalogyAuthenticatorController;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.CasWebSecurityConfigurer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ScopedProxyMode;

import java.util.List;

/**
 * This is {@link InalogyAuthenticatorControllerConfiguration}.
 * Configuration class for Inalogy Authenticator controllers.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
@Configuration(value = "InalogyAuthenticatorControllerConfiguration", proxyBeanMethods = false)
public class InalogyAuthenticatorControllerConfiguration {

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "casInalogyEndpointConfigurer")
    public CasWebSecurityConfigurer<Void> casInalogyEndpointConfigurer() {
        return new CasWebSecurityConfigurer<>() {
            @Override
            public List<String> getIgnoredEndpoints() {
                val submit = "/inalogy/submit";
                val validate = "/inalogy/validate";
                val terminate = "/inalogy/terminate";
                val pushIdChange = "/inalogy/push-id-change";
                val checkStatus = "/inalogy/check";
                return List.of(submit, terminate, validate, pushIdChange, checkStatus);
            }
        };
    }

    @Bean
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorController")
    public InalogyAuthenticatorController inalogyAuthenticatorController(
            @Qualifier("inalogyAuthenticatorInstance")
            final IInalogyAuthenticator inalogyAuthenticatorInstance) {
        return new InalogyAuthenticatorController(inalogyAuthenticatorInstance);
    }
}
