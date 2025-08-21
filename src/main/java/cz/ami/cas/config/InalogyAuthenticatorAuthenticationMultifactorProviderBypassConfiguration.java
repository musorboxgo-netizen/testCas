package cz.ami.cas.config;

import cz.ami.cas.inauth.InalogyAuthenticatorBypassEvaluator;
import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.bypass.*;
import org.apereo.cas.util.spring.beans.BeanCondition;
import org.apereo.cas.util.spring.beans.BeanSupplier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;

import java.util.Optional;

@EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
@Slf4j
@Configuration(value = "InalogyAuthenticatorAuthenticationMultifactorProviderBypassConfiguration", proxyBeanMethods = false)
class InalogyAuthenticatorAuthenticationMultifactorProviderBypassConfiguration {

    @ConditionalOnMissingBean(name = "inalogyAuthenticatorBypassEvaluator")
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorBypassEvaluator(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {

        val bypass = new DefaultChainingMultifactorAuthenticationBypassProvider(applicationContext);
        val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
        val currentBypassEvaluators = applicationContext.getBeansWithAnnotation(InalogyAuthenticatorBypassEvaluator.class).values();
        currentBypassEvaluators
                .stream()
                .filter(BeanSupplier::isNotProxy)
                .map(MultifactorAuthenticationProviderBypassEvaluator.class::cast)
                .filter(evaluator -> !evaluator.isEmpty())
                .map(evaluator -> evaluator.belongsToMultifactorAuthenticationProvider(providerId))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .sorted(AnnotationAwareOrderComparator.INSTANCE)
                .forEach(bypass::addMultifactorAuthenticationProviderBypassEvaluator);
        return bypass;
    }

    @ConditionalOnMissingBean(name = "inalogyAuthenticatorRegisteredServicePrincipalAttributeMultifactorAuthenticationProviderBypassEvaluator")
    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorRegisteredServicePrincipalAttributeMultifactorAuthenticationProviderBypassEvaluator(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
        return new RegisteredServicePrincipalAttributeMultifactorAuthenticationProviderBypassEvaluator(providerId, applicationContext);
    }

    @ConditionalOnMissingBean(name = "inalogyAuthenticatorRestMultifactorAuthenticationProviderBypass")
    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorRestMultifactorAuthenticationProviderBypass(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        
        val props = inalogyMfaProperties.getBypass();
        return BeanSupplier.of(MultifactorAuthenticationProviderBypassEvaluator.class)
                .when(BeanCondition.on("cas.authn.mfa.inalogyMfaProperties.bypass.rest.url").given(applicationContext.getEnvironment()))
                .supply(() -> {
                    val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
                    return new RestMultifactorAuthenticationProviderBypassEvaluator(props, providerId, applicationContext);
                })
                .otherwiseProxy()
                .get();
    }

    @ConditionalOnMissingBean(name = "inalogyAuthenticatorGroovyMultifactorAuthenticationProviderBypass")
    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorGroovyMultifactorAuthenticationProviderBypass(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {

        return BeanSupplier.of(MultifactorAuthenticationProviderBypassEvaluator.class)
                .when(BeanCondition.on("cas.authn.mfa.inalogyMfaProperties.bypass.groovy.location").exists().given(applicationContext.getEnvironment()))
                .supply(() -> {
                    
                    val props = inalogyMfaProperties.getBypass();
                    val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
                    return new GroovyMultifactorAuthenticationProviderBypassEvaluator(props, providerId, applicationContext);
                })
                .otherwiseProxy()
                .get();

    }

    @ConditionalOnMissingBean(name = "inalogyAuthenticatorHttpRequestMultifactorAuthenticationProviderBypass")
    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorHttpRequestMultifactorAuthenticationProviderBypass(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        
        val props = inalogyMfaProperties.getBypass();
        val bypassActive = StringUtils.isNotBlank(props.getHttpRequestHeaders()) || StringUtils.isNotBlank(props.getHttpRequestRemoteAddress());
        return BeanSupplier.of(MultifactorAuthenticationProviderBypassEvaluator.class)
                .when(bypassActive)
                .supply(() -> {
                    val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
                    return new HttpRequestMultifactorAuthenticationProviderBypassEvaluator(props, providerId, applicationContext);
                })
                .otherwiseProxy()
                .get();
    }

    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorCredentialMultifactorAuthenticationProviderBypass")
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorCredentialMultifactorAuthenticationProviderBypass(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        
        val props = inalogyMfaProperties.getBypass();
        return BeanSupplier.of(MultifactorAuthenticationProviderBypassEvaluator.class)
                .when(StringUtils.isNotBlank(props.getCredentialClassType()))
                .supply(() -> {
                    val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
                    return new CredentialMultifactorAuthenticationProviderBypassEvaluator(props, providerId, applicationContext);
                })
                .otherwiseProxy()
                .get();
    }

    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorRegisteredServiceMultifactorAuthenticationProviderBypass")
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorRegisteredServiceMultifactorAuthenticationProviderBypass(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        
        val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
        return new RegisteredServiceMultifactorAuthenticationProviderBypassEvaluator(providerId, applicationContext);
    }

    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorPrincipalMultifactorAuthenticationProviderBypass")
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorPrincipalMultifactorAuthenticationProviderBypass(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        
        val props = inalogyMfaProperties.getBypass();
        return BeanSupplier.of(MultifactorAuthenticationProviderBypassEvaluator.class)
                .when(StringUtils.isNotBlank(props.getPrincipalAttributeName()))
                .supply(() -> {
                    val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
                    return new PrincipalMultifactorAuthenticationProviderBypassEvaluator(props, providerId, applicationContext);
                })
                .otherwiseProxy()
                .get();
    }

    @Bean
    @InalogyAuthenticatorBypassEvaluator
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorAuthenticationMultifactorAuthenticationProviderBypass")
    public MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorAuthenticationMultifactorAuthenticationProviderBypass(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        
        val props = inalogyMfaProperties.getBypass();
        val bypassActive = StringUtils.isNotBlank(props.getAuthenticationAttributeName())
                || StringUtils.isNotBlank(props.getAuthenticationHandlerName())
                || StringUtils.isNotBlank(props.getAuthenticationMethodName());
        return BeanSupplier.of(MultifactorAuthenticationProviderBypassEvaluator.class)
                .when(bypassActive)
                .supply(() -> {
                    val providerId = StringUtils.defaultIfBlank(inalogyMfaProperties.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
                    return new AuthenticationMultifactorAuthenticationProviderBypassEvaluator(props, providerId, applicationContext);
                })
                .otherwiseProxy()
                .get();
    }
}
