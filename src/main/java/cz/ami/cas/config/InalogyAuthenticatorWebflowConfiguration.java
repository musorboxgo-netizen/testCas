package cz.ami.cas.config;

import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import cz.ami.cas.inauth.hazelcast.mfa.MfaRequestMap;
import cz.ami.cas.inauth.hazelcast.registration.RegistrationRequestMap;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import cz.ami.cas.inauth.credential.repository.BaseInalogyAuthenticatorTokenCredentialRepository;
import cz.ami.cas.inauth.token.InalogyAuthenticatorToken;
import cz.ami.cas.inauth.web.flow.InalogyWebflowConstants;
import cz.ami.cas.inauth.web.flow.action.account.InalogyMultifactorAuthenticationAccountProfilePrepareAction;
import cz.ami.cas.inauth.web.flow.action.account.InalogyMultifactorAuthenticationAccountProfileRegistrationAction;
import cz.ami.cas.inauth.web.flow.InalogyMultifactorAuthenticationAccountProfileWebflowConfigurer;
import cz.ami.cas.inauth.web.flow.action.*;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.authentication.device.MultifactorAuthenticationDeviceManager;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.features.CasFeatureModule;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialValidator;
import org.apereo.cas.util.spring.boot.ConditionalOnFeatureEnabled;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.apereo.cas.web.flow.actions.DefaultMultifactorAuthenticationDeviceProviderAction;
import org.apereo.cas.web.flow.actions.MultifactorAuthenticationDeviceProviderAction;
import org.apereo.cas.web.flow.actions.WebflowActionBeanSupplier;
import org.apereo.cas.web.flow.configurer.CasMultifactorWebflowCustomizer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.Ordered;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.execution.Action;

import java.util.List;

/**
 * This is {@link InalogyAuthenticatorWebflowConfiguration}.
 * Configuration class for Inalogy Authenticator webflow.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
@Slf4j
@Configuration(value = "InalogyAuthenticatorWebflowConfiguration", proxyBeanMethods = false)
public class InalogyAuthenticatorWebflowConfiguration {

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_DEVICE_PROVIDER)
    public MultifactorAuthenticationDeviceProviderAction inalogyAccountDeviceProviderAction(
            @Qualifier("inalogyAuthenticatorDeviceManager")
            final MultifactorAuthenticationDeviceManager inalogyAuthenticatorDeviceManager) {
        return new DefaultMultifactorAuthenticationDeviceProviderAction(inalogyAuthenticatorDeviceManager);
    }
    
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyPrepareLoginAction")
    public Action inalogyPrepareLoginAction(
        final ConfigurableApplicationContext applicationContext,
        @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
        final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
        final CasConfigurationProperties casProperties) {
        return WebflowActionBeanSupplier.builder()
            .withApplicationContext(applicationContext)
            .withProperties(casProperties)
            .withAction(() -> new InalogyPrepareLoginAction(casProperties, inalogyAuthenticatorAccountRegistry))
            .withId("inalogyPrepareLoginAction")
            .build()
            .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION)
    public Action inalogyAccountCheckRegistrationAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
            @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
            final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyAuthenticatorAccountCheckRegistrationAction(inalogyAuthenticatorAccountRegistry, casProperties, inalogyMfaProperties.getCore()))
                .withId(InalogyWebflowConstants.ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION)
    public Action inalogySaveAccountRegistrationAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
            @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
            final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
            @Qualifier("inalogyAuthenticatorOneTimeTokenCredentialValidator")
            final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> validator,
            @Qualifier(RegistrationRequestMap.BEAN_NAME)
            RegistrationRequestMap registrationRequestMap
            ) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyAuthenticatorSaveRegistrationAction(
                        registrationRequestMap, inalogyAuthenticatorAccountRegistry, inalogyMfaProperties.getCore()))
                .withId(InalogyWebflowConstants.ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION)
    public Action inalogyValidateSelectedRegistrationAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(InalogyAuthenticatorValidateSelectedRegistrationAction::new)
                .withId(InalogyWebflowConstants.ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_INALOGY_DECIDE_DOWNLOAD)
    public Action inalogyDisplayDownloadAction(
            final ConfigurableApplicationContext applicationContext,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
            final CasConfigurationProperties casProperties) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyAuthenticatorDecideQrDisplay(inalogyMfaProperties))
                .withId(InalogyWebflowConstants.ACTION_ID_INALOGY_DECIDE_DOWNLOAD)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAccountCreateRegistrationAction")
    public Action inalogyAccountCreateRegistrationAction(
        final ConfigurableApplicationContext applicationContext,
        final CasConfigurationProperties casProperties,
        final InalogyAuthenticatorMultifactorProperties inalogy,
        @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
        final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
        @Qualifier(RegistrationRequestMap.BEAN_NAME)
        RegistrationRequestMap registrationRequestMap
        ) {
        return WebflowActionBeanSupplier.builder()
            .withApplicationContext(applicationContext)
            .withProperties(casProperties)
            .withAction(() -> new InalogyAccountCreateRegistrationAction(
                inalogyAuthenticatorAccountRegistry, registrationRequestMap, inalogy.getCore()))
            .withId("inalogyAccountCreateRegistrationAction")
            .build()
            .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_INALOGY_VALIDATE_TOKEN)
    public Action inalogyValidateTokenAction(
            @Qualifier("inalogyAuthenticatorOneTimeTokenCredentialValidator")
            final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> inalogyAuthenticatorOneTimeTokenCredentialValidator,
            final ConfigurableApplicationContext applicationContext,
            @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
            final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
            @Qualifier(MfaRequestMap.BEAN_NAME)
            final MfaRequestMap mfaRequestMap,
            final CasConfigurationProperties casProperties) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyAuthenticatorValidateTokenAction(casProperties,
                        inalogyAuthenticatorAccountRegistry, mfaRequestMap, inalogyAuthenticatorOneTimeTokenCredentialValidator))
                .withId(InalogyWebflowConstants.ACTION_ID_INALOGY_VALIDATE_TOKEN)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE)
    public Action inalogyPushCheckResponseAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            @Qualifier("inalogyAuthenticatorInstance")
            final IInalogyAuthenticator inalogyAuthenticator
            ) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyPushCheckResponseAction(inalogyAuthenticator))
                .withId(InalogyWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_INALOGY_PUSH_INIT)
    public Action inalogyPushInitAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            final InalogyAuthenticatorMultifactorProperties multifactorProperties,
            @Qualifier("inalogyAuthenticatorInstance")
            final IInalogyAuthenticator inalogyAuthenticator
    ) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyInitiatePushAuthenticationAction(inalogyAuthenticator, multifactorProperties.getCore()))
                .withId(InalogyWebflowConstants.ACTION_ID_INALOGY_PUSH_INIT)
                .build()
                .get();
    }

    @Configuration(value = "InalogyAuthenticatorAccountProfileWebflowConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
    @ConditionalOnFeatureEnabled(feature = CasFeatureModule.FeatureCatalog.AccountManagement, enabledByDefault = false)
    @AutoConfigureOrder(Ordered.LOWEST_PRECEDENCE)
    static class InalogyAuthenticatorAccountProfileWebflowConfiguration {

        @ConditionalOnMissingBean(name = "inalogyAccountProfileWebflowConfigurer")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public CasWebflowConfigurer inalogyAccountProfileWebflowConfigurer(
                final CasConfigurationProperties casProperties,
                final ConfigurableApplicationContext applicationContext,
                @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_DEFINITION_REGISTRY)
                final FlowDefinitionRegistry flowDefinitionRegistry,
                @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER_SERVICES)
                final FlowBuilderServices flowBuilderServices) {
            return new InalogyMultifactorAuthenticationAccountProfileWebflowConfigurer(flowBuilderServices,
                    flowDefinitionRegistry, applicationContext, casProperties);
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = "inalogyAccountCasWebflowExecutionPlanConfigurer")
        public CasWebflowExecutionPlanConfigurer inalogyAccountCasWebflowExecutionPlanConfigurer(
                @Qualifier("inalogyAccountProfileWebflowConfigurer")
                final CasWebflowConfigurer inalogyAccountProfileWebflowConfigurer) {
            return plan -> plan.registerWebflowConfigurer(inalogyAccountProfileWebflowConfigurer);
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_DEVICE_PROVIDER)
        public MultifactorAuthenticationDeviceProviderAction inalogyAccountDeviceProviderAction(
                @Qualifier("inalogyAuthenticatorDeviceManager")
                final MultifactorAuthenticationDeviceManager inalogyAuthenticatorDeviceManager) {
            return new DefaultMultifactorAuthenticationDeviceProviderAction(inalogyAuthenticatorDeviceManager);
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_PREPARE)
        public Action inalogyAccountProfilePrepareAction(
                final ConfigurableApplicationContext applicationContext,
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider,
                final CasConfigurationProperties casProperties,
                final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
                @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
                final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry) {
            return WebflowActionBeanSupplier.builder()
                    .withApplicationContext(applicationContext)
                    .withProperties(casProperties)
                    .withAction(() -> new InalogyMultifactorAuthenticationAccountProfilePrepareAction(inalogyAuthenticatorAccountRegistry,
                            inalogyAuthenticatorMultifactorAuthenticationProvider, inalogyMfaProperties.getCore()))
                    .withId(InalogyWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_PREPARE)
                    .build()
                    .get();
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = InalogyWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_REGISTRATION)
        public Action inalogyAccountProfileRegistrationAction(
                final ConfigurableApplicationContext applicationContext,
                final CasConfigurationProperties casProperties,
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider) {
            return WebflowActionBeanSupplier.builder()
                    .withApplicationContext(applicationContext)
                    .withProperties(casProperties)
                    .withAction(() -> new InalogyMultifactorAuthenticationAccountProfileRegistrationAction(inalogyAuthenticatorMultifactorAuthenticationProvider))
                    .withId(InalogyWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_REGISTRATION)
                    .build()
                    .get();
        }

    }

    @Bean
    @ConditionalOnMissingBean(name = "inalogyMultifactorWebflowCustomizers")
    public List<CasMultifactorWebflowCustomizer> inalogyMultifactorWebflowCustomizers() {
        return List.of();
    }
}
