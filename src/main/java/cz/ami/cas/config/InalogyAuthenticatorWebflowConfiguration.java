package cz.ami.cas.config;

import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.authenticator.repository.TemporaryAccountStorage;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import cz.ami.cas.inauth.credential.repository.BaseInalogyAuthenticatorTokenCredentialRepository;
import cz.ami.cas.inauth.token.InalogyAuthenticatorToken;
import cz.ami.cas.inauth.web.flow.*;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.device.MultifactorAuthenticationDeviceManager;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialValidator;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.apereo.cas.web.flow.actions.DefaultMultifactorAuthenticationDeviceProviderAction;
import org.apereo.cas.web.flow.actions.MultifactorAuthenticationDeviceProviderAction;
import org.apereo.cas.web.flow.actions.WebflowActionBeanSupplier;
import org.apereo.cas.web.flow.configurer.CasMultifactorWebflowCustomizer;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.webflow.config.FlowDefinitionRegistryBuilder;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.FlowBuilder;
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
@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
@Configuration(value = "InalogyAuthenticatorWebflowConfiguration", proxyBeanMethods = false)
public class InalogyAuthenticatorWebflowConfiguration {

    private static final int WEBFLOW_CONFIGURER_ORDER = 101;
    
    
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorMultifactorWebflowConfigurer")
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public CasWebflowConfigurer inalogyAuthenticatorMultifactorWebflowConfigurer(
            final CasConfigurationProperties casProperties,
            final ConfigurableApplicationContext applicationContext,
            @Qualifier("inalogyAuthenticatorFlowRegistry")
            final FlowDefinitionRegistry inalogyAuthenticatorFlowRegistry,
            @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_DEFINITION_REGISTRY)
            final FlowDefinitionRegistry flowDefinitionRegistry,
            @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER_SERVICES)
            final FlowBuilderServices flowBuilderServices) {
        val cfg = new InalogyAuthenticatorMultifactorWebflowConfigurer(flowBuilderServices,
                flowDefinitionRegistry, inalogyAuthenticatorFlowRegistry, applicationContext, casProperties,
                MultifactorAuthenticationWebflowUtils.getMultifactorAuthenticationWebflowCustomizers(applicationContext));
        cfg.setOrder(WEBFLOW_CONFIGURER_ORDER);
        return cfg;
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorCasWebflowExecutionPlanConfigurer")
    public CasWebflowExecutionPlanConfigurer inalogyAuthenticatorCasWebflowExecutionPlanConfigurer(
        @Qualifier("inalogyAuthenticatorMultifactorWebflowConfigurer")
        final CasWebflowConfigurer inalogyAuthenticatorMultifactorWebflowConfigurer) {
        return plan -> plan.registerWebflowConfigurer(inalogyAuthenticatorMultifactorWebflowConfigurer);
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_DEVICE_PROVIDER)
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
    @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION)
    public Action inalogyAccountCheckRegistrationAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
            final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyAuthenticatorAccountCheckRegistrationAction(inalogyAuthenticatorAccountRegistry, casProperties))
                .withId(CasWebflowConstants.ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION)
    public Action inalogySaveAccountRegistrationAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
            final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
            @Qualifier("inalogyAuthenticatorOneTimeTokenCredentialValidator")
            final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> validator,
            @Qualifier("inalogyTemporaryAccountStorage")
            final TemporaryAccountStorage temporaryAccountStorage
            ) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyAuthenticatorSaveRegistrationAction(
                        temporaryAccountStorage, inalogyAuthenticatorAccountRegistry, casProperties))
                .withId(CasWebflowConstants.ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyCheckAccountRegStatusAction")
    public Action inalogyCheckAccountRegStatusAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            @Qualifier("inalogyTemporaryAccountStorage")
            final TemporaryAccountStorage temporaryAccountStorage
    ) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyCheckAccountRegStatusAction(temporaryAccountStorage))
                .withId("inalogyCheckAccountRegStatusAction")
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION)
    public Action inalogyValidateSelectedRegistrationAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(InalogyAuthenticatorValidateSelectedRegistrationAction::new)
                .withId(CasWebflowConstants.ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION)
                .build()
                .get();
    }
    
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAccountCreateRegistrationAction")
    public Action inalogyAccountCreateRegistrationAction(
        final ConfigurableApplicationContext applicationContext,
        final CasConfigurationProperties casProperties,
        @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
        final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
        @Qualifier("inalogyTemporaryAccountStorage")
        final TemporaryAccountStorage temporaryAccountStorage
        ) {
        val inalogy = casProperties.getAuthn().getMfa().getInalogy().getCore();
        return WebflowActionBeanSupplier.builder()
            .withApplicationContext(applicationContext)
            .withProperties(casProperties)
            .withAction(() -> new InalogyAccountCreateRegistrationAction(
                inalogyAuthenticatorAccountRegistry, temporaryAccountStorage, inalogy))
            .withId("inalogyAccountCreateRegistrationAction")
            .build()
            .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_INALOGY_VALIDATE_TOKEN)
    public Action inalogyValidateTokenAction(
            @Qualifier("inalogyAuthenticatorOneTimeTokenCredentialValidator")
            final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> inalogyAuthenticatorOneTimeTokenCredentialValidator,
            final ConfigurableApplicationContext applicationContext,
            @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
            final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
            final CasConfigurationProperties casProperties) {
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyAuthenticatorValidateTokenAction(casProperties,
                        inalogyAuthenticatorAccountRegistry, inalogyAuthenticatorOneTimeTokenCredentialValidator))
                .withId(CasWebflowConstants.ACTION_ID_INALOGY_VALIDATE_TOKEN)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE)
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
                .withId(CasWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE)
                .build()
                .get();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_INALOGY_PUSH_INIT)
    public Action inalogyPushInitAction(
            final ConfigurableApplicationContext applicationContext,
            final CasConfigurationProperties casProperties,
            @Qualifier("inalogyAuthenticatorInstance")
            final IInalogyAuthenticator inalogyAuthenticator
    ) {
        val prefix = casProperties.getServer().getPrefix();
        return WebflowActionBeanSupplier.builder()
                .withApplicationContext(applicationContext)
                .withProperties(casProperties)
                .withAction(() -> new InalogyPushInitAction(inalogyAuthenticator, prefix))
                .withId(CasWebflowConstants.ACTION_ID_INALOGY_PUSH_INIT)
                .build()
                .get();
    }
    
    @Bean
    @ConditionalOnMissingBean(name = "inalogyMultifactorWebflowCustomizers")
    public List<CasMultifactorWebflowCustomizer> inalogyMultifactorWebflowCustomizers() {
        return List.of();
    }

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorFlowRegistry")
    public FlowDefinitionRegistry inalogyAuthenticatorFlowRegistry(
        final CasConfigurationProperties casProperties,
        final ConfigurableApplicationContext applicationContext,
        @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER_SERVICES)
        final FlowBuilderServices flowBuilderServices,
        @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER)
        final FlowBuilder flowBuilder) {
        val builder = new FlowDefinitionRegistryBuilder(applicationContext, flowBuilderServices);
        builder.addFlowBuilder(flowBuilder, casProperties.getAuthn().getMfa().getInalogy().getId());
        return builder.build();
    }
}
