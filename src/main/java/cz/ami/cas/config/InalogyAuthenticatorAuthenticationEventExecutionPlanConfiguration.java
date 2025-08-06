package cz.ami.cas.config;

import cz.ami.cas.inauth.InalogyAuthenticatorAuthenticationHandler;
import cz.ami.cas.inauth.InalogyAuthenticatorMultifactorAuthenticationProvider;
import cz.ami.cas.inauth.service.InalogyAuthenticatorService;
import cz.ami.cas.inauth.service.InalogyMessagingService;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.authenticator.repository.IInalogyPushAuthenticationRepository;
import cz.ami.cas.inauth.authenticator.repository.InMemoryInalogyPushAuthenticationRepository;
import cz.ami.cas.inauth.authenticator.repository.TemporaryAccountStorage;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorOneTimeTokenCredentialValidator;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import cz.ami.cas.inauth.credential.repository.BaseInalogyAuthenticatorTokenCredentialRepository;
import cz.ami.cas.inauth.credential.repository.InMemoryInalogyAuthenticatorTokenCredentialRepository;
import cz.ami.cas.inauth.token.InalogyAuthenticatorToken;
import cz.ami.cas.inauth.token.InalogyAuthenticatorTokenRepositoryCleaner;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.bypass.MultifactorAuthenticationProviderBypassEvaluator;
import org.apereo.cas.authentication.device.MultifactorAuthenticationDeviceManager;
import org.apereo.cas.authentication.handler.ByCredentialTypeAuthenticationHandlerResolver;
import org.apereo.cas.authentication.metadata.AuthenticationContextAttributeMetaDataPopulator;
import org.apereo.cas.authentication.metadata.MultifactorAuthenticationProviderMetadataPopulator;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.PrincipalFactoryUtils;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.features.CasFeatureModule;
import cz.ami.cas.inauth.web.flow.account.*;
import org.apereo.cas.otp.repository.credentials.*;
import org.apereo.cas.otp.repository.token.OneTimeTokenRepository;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.cipher.CipherExecutorUtils;
import org.apereo.cas.util.cipher.JasyptNumberCipherExecutor;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.util.spring.beans.BeanCondition;
import org.apereo.cas.util.spring.beans.BeanSupplier;
import org.apereo.cas.util.spring.boot.ConditionalOnFeatureEnabled;
import org.apereo.cas.util.thread.Cleanable;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.apereo.cas.web.flow.actions.DefaultMultifactorAuthenticationDeviceProviderAction;
import org.apereo.cas.web.flow.actions.MultifactorAuthenticationDeviceProviderAction;
import org.apereo.cas.web.flow.actions.WebflowActionBeanSupplier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.Ordered;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.execution.Action;

@EnableConfigurationProperties(CasConfigurationProperties.class)
@Slf4j
@Configuration(value = "InalogyAuthenticatorAuthenticationEventExecutionPlanConfiguration", proxyBeanMethods = false)
public class InalogyAuthenticatorAuthenticationEventExecutionPlanConfiguration {

    @Configuration(value = "InalogyAuthenticatorAuthenticationEventExecutionPlanHandlerConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class InalogyAuthenticatorAuthenticationEventExecutionPlanHandlerConfiguration {
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorAuthenticationHandler")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public AuthenticationHandler inalogyAuthenticatorAuthenticationHandler(
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final ObjectProvider<MultifactorAuthenticationProvider> multifactorAuthenticationProvider,
                final CasConfigurationProperties casProperties,
                @Qualifier("inalogyPrincipalFactory")
                final PrincipalFactory inalogyPrincipalFactory,
                @Qualifier("inalogyAuthenticatorOneTimeTokenCredentialValidator")
                final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> inalogyAuthenticatorOneTimeTokenCredentialValidator,
                @Qualifier(ServicesManager.BEAN_NAME)
                final ServicesManager servicesManager) {
            val inalogy = casProperties.getAuthn().getMfa().getInalogy();
            return new InalogyAuthenticatorAuthenticationHandler(inalogy.getName(), servicesManager,
                    inalogyPrincipalFactory, inalogyAuthenticatorOneTimeTokenCredentialValidator,
                    inalogy.getOrder(), multifactorAuthenticationProvider);
        }

    }

    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationCoreConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class InalogyAuthenticatorMultifactorAuthenticationCoreConfiguration {
        private static final BeanCondition CONDITION_SCRATCH_CODE =
                BeanCondition.on("cas.authn.mfa.inalogy.core.scratch-codes.encryption.key");

        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @Bean
        @ConditionalOnMissingBean(name = IInalogyPushAuthenticationRepository.BEAN_NAME)
        public IInalogyPushAuthenticationRepository inalogyPushAuthenticationRepository() {
            return new InMemoryInalogyPushAuthenticationRepository();
        }

        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @Bean
        @ConditionalOnMissingBean(name = "inalogyTemporaryAccountStorage")
        public TemporaryAccountStorage inalogyTemporaryAccountStorage() {
            return new TemporaryAccountStorage();
        }

        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @Bean
        @ConditionalOnMissingBean(name = "inalogyMessagingService")
        public InalogyMessagingService inalogyMessagingService(final CasConfigurationProperties casProperties) {
            val messagingService = casProperties.getAuthn().getMfa().getInalogy().getMessagingService();
            return new InalogyMessagingService(messagingService);
        }

        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @Bean
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorInstance")
        public IInalogyAuthenticator inalogyAuthenticatorInstance(
                final CasConfigurationProperties casProperties,
                @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
                final BaseInalogyAuthenticatorTokenCredentialRepository credentialRepository,
                @Qualifier(IInalogyPushAuthenticationRepository.BEAN_NAME)
                final IInalogyPushAuthenticationRepository inalogyPushAuthenticationRepository,
                @Qualifier("inalogyMessagingService")
                final InalogyMessagingService messagingService,
                @Qualifier("inalogyTemporaryAccountStorage")
                final TemporaryAccountStorage temporaryAccountStorage
                ) {
            val inalogy = casProperties.getAuthn().getMfa().getInalogy().getCore();
            return new InalogyAuthenticatorService(inalogy, credentialRepository,
                    inalogyPushAuthenticationRepository, messagingService, temporaryAccountStorage);
        }

        @ConditionalOnMissingBean(name = "inalogyAuthenticatorAccountCipherExecutor")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public CipherExecutor inalogyAuthenticatorAccountCipherExecutor(final CasConfigurationProperties casProperties) {
            val crypto = casProperties.getAuthn().getMfa().getInalogy().getCrypto();
            if (crypto.isEnabled()) {
                return CipherExecutorUtils.newStringCipherExecutor(crypto, OneTimeTokenAccountCipherExecutor.class);
            }
            LOGGER.warn("Inalogy Authenticator one-time token account encryption/signing is turned off. "
                    + "Consider turning on encryption, signing to securely and safely store one-time token accounts.");
            return CipherExecutor.noOp();
        }

        @ConditionalOnMissingBean(name = "inalogyAuthenticatorScratchCodesCipherExecutor")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public CipherExecutor inalogyAuthenticatorScratchCodesCipherExecutor(final ApplicationContext applicationContext,
                                                                            final CasConfigurationProperties casProperties) {
            return BeanSupplier.of(CipherExecutor.class)
                    .when(CONDITION_SCRATCH_CODE.given(applicationContext.getEnvironment()))
                    .supply(() -> {
                        val key = casProperties.getAuthn().getMfa().getInalogy().getCore().getScratchCodes().getEncryption().getKey();
                        return new JasyptNumberCipherExecutor(key, "inalogyAuthenticatorScratchCodesCipherExecutor");
                    })
                    .otherwise(() -> {
                        LOGGER.warn("Inalogy Authenticator scratch codes encryption key is not defined. "
                                + "Consider defining the encryption key to securely and safely store scratch codes.");
                        return CipherExecutor.noOp();
                    })
                    .get();
        }

        @ConditionalOnMissingBean(name = "inalogyPrincipalFactory")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public PrincipalFactory inalogyPrincipalFactory() {
            return PrincipalFactoryUtils.newPrincipalFactory();
        }

    }

    @Configuration(value = "InalogyAuthenticatorAuthenticationEventExecutionPlanMetadataConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class InalogyAuthenticatorAuthenticationEventExecutionPlanMetadataConfiguration {
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorAuthenticationMetaDataPopulator")
        public AuthenticationMetaDataPopulator inalogyAuthenticatorAuthenticationMetaDataPopulator(
                final CasConfigurationProperties casProperties,
                @Qualifier("inalogyAuthenticatorAuthenticationHandler")
                final AuthenticationHandler inalogyAuthenticatorAuthenticationHandler,
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider) {
            return new AuthenticationContextAttributeMetaDataPopulator(
                    casProperties.getAuthn().getMfa().getCore().getAuthenticationContextAttribute(), inalogyAuthenticatorAuthenticationHandler,
                    inalogyAuthenticatorMultifactorAuthenticationProvider.getId());
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator")
        public AuthenticationMetaDataPopulator inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator(
                @Qualifier(ServicesManager.BEAN_NAME)
                final ServicesManager servicesManager,
                final CasConfigurationProperties casProperties,
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final ObjectProvider<MultifactorAuthenticationProvider> multifactorAuthenticationProvider) {
            val authenticationContextAttribute = casProperties.getAuthn().getMfa().getCore().getAuthenticationContextAttribute();
            return new MultifactorAuthenticationProviderMetadataPopulator(authenticationContextAttribute,
                    multifactorAuthenticationProvider, servicesManager);
        }
    }

//    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationWebConfiguration", proxyBeanMethods = false)
//    @EnableConfigurationProperties(CasConfigurationProperties.class)
//    static class InalogyAuthenticatorMultifactorAuthenticationWebConfiguration {
//        @Bean
//        @ConditionalOnAvailableEndpoint
//        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
//        public InalogyAuthenticatorTokenCredentialRepositoryEndpoint inalogyAuthenticatorTokenCredentialRepositoryEndpoint(
//                final ConfigurableApplicationContext applicationContext,
//                final CasConfigurationProperties casProperties,
//                @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
//                final ObjectProvider<OneTimeTokenCredentialRepository> inalogyAuthenticatorAccountRegistry) {
//            return new InalogyAuthenticatorTokenCredentialRepositoryEndpoint(
//                    casProperties, applicationContext, inalogyAuthenticatorAccountRegistry);
//        }
//    }

    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationPlanConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class InalogyAuthenticatorMultifactorAuthenticationPlanConfiguration {
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorAuthenticationEventExecutionPlanConfigurer")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public AuthenticationEventExecutionPlanConfigurer inalogyAuthenticatorAuthenticationEventExecutionPlanConfigurer(
                @Qualifier("inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator")
                final AuthenticationMetaDataPopulator inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator,
                final CasConfigurationProperties casProperties,
                @Qualifier("inalogyAuthenticatorAuthenticationHandler")
                final AuthenticationHandler inalogyAuthenticatorAuthenticationHandler,
                @Qualifier("inalogyAuthenticatorAuthenticationMetaDataPopulator")
                final AuthenticationMetaDataPopulator inalogyAuthenticatorAuthenticationMetaDataPopulator) {
            return plan -> {
                if (StringUtils.isNotBlank(casProperties.getAuthn().getMfa().getInalogy().getCore().getIssuer())) {
                    plan.registerAuthenticationHandler(inalogyAuthenticatorAuthenticationHandler);
                    plan.registerAuthenticationMetadataPopulator(inalogyAuthenticatorAuthenticationMetaDataPopulator);
                    plan.registerAuthenticationMetadataPopulator(inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator);
                    plan.registerAuthenticationHandlerResolver(new ByCredentialTypeAuthenticationHandlerResolver(InalogyAuthenticatorTokenCredential.class));
                }
            };
        }
    }
    
    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationTokenConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class InalogyAuthenticatorMultifactorAuthenticationTokenConfiguration {
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorOneTimeTokenCredentialValidator")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> inalogyAuthenticatorOneTimeTokenCredentialValidator(
                @Qualifier("inalogyAuthenticatorInstance")
                final IInalogyAuthenticator inalogyAuthenticatorInstance,
                @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
                final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry,
                @Qualifier(OneTimeTokenRepository.BEAN_NAME)
                final OneTimeTokenRepository oneTimeTokenAuthenticatorTokenRepository) {
            return new InalogyAuthenticatorOneTimeTokenCredentialValidator(inalogyAuthenticatorInstance,
                    oneTimeTokenAuthenticatorTokenRepository, inalogyAuthenticatorAccountRegistry);
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @Lazy(false)
        public Cleanable inalogyAuthenticatorTokenRepositoryCleaner(
                final ConfigurableApplicationContext applicationContext,
                @Qualifier(OneTimeTokenRepository.BEAN_NAME)
                final OneTimeTokenRepository repository) {
            return BeanSupplier.of(Cleanable.class)
                    .when(BeanCondition.on("cas.authn.mfa.inalogy.cleaner.schedule.enabled").isTrue().evenIfMissing()
                            .given(applicationContext.getEnvironment()))
                    .supply(() -> new InalogyAuthenticatorTokenRepositoryCleaner(repository))
                    .otherwiseProxy()
                    .get();
        }

        @ConditionalOnMissingBean(name = "inalogyAuthenticatorDeviceManager")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public MultifactorAuthenticationDeviceManager inalogyAuthenticatorDeviceManager(
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final ObjectProvider<MultifactorAuthenticationProvider> inalogyAuthenticatorMultifactorAuthenticationProvider,
                @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
                final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry) {
            return new OneTimeTokenCredentialDeviceManager(inalogyAuthenticatorAccountRegistry,
                    inalogyAuthenticatorMultifactorAuthenticationProvider);
        }

        @ConditionalOnMissingBean(name = BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public BaseInalogyAuthenticatorTokenCredentialRepository inalogyAuthenticatorAccountRegistry(
                @Lazy @Qualifier("inalogyAuthenticatorInstance")
                final IInalogyAuthenticator inalogyAuthenticatorInstance,
                @Qualifier("inalogyAuthenticatorAccountCipherExecutor")
                final CipherExecutor inalogyAuthenticatorAccountCipherExecutor,
                @Qualifier("inalogyAuthenticatorScratchCodesCipherExecutor")
                final CipherExecutor inalogyAuthenticatorScratchCodesCipherExecutor) {
            return new InMemoryInalogyAuthenticatorTokenCredentialRepository(
                    inalogyAuthenticatorAccountCipherExecutor, inalogyAuthenticatorScratchCodesCipherExecutor, inalogyAuthenticatorInstance);
        }
    }
    
    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationProviderConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
    static class InalogyAuthenticatorMultifactorAuthenticationProviderConfiguration {
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorMultifactorAuthenticationProvider")
        public MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider(
                final CasConfigurationProperties casProperties,
                @Qualifier("inalogyAuthenticatorBypassEvaluator")
                final MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorBypassEvaluator,
                @Qualifier("failureModeEvaluator")
                final MultifactorAuthenticationFailureModeEvaluator failureModeEvaluator,
                @Qualifier("inalogyAuthenticatorDeviceManager")
                final MultifactorAuthenticationDeviceManager inalogyAuthenticatorDeviceManager) {
            val inalogy = casProperties.getAuthn().getMfa().getInalogy();
            val provider = new InalogyAuthenticatorMultifactorAuthenticationProvider();
            provider.setBypassEvaluator(inalogyAuthenticatorBypassEvaluator);
            provider.setFailureMode(inalogy.getFailureMode());
            provider.setFailureModeEvaluator(failureModeEvaluator);
            provider.setOrder(inalogy.getRank());
            provider.setId(inalogy.getId());
            provider.setDeviceManager(inalogyAuthenticatorDeviceManager);
            return provider;
        }
    }

    @Configuration(value = "InalogyAuthenticatorAccountProfileWebflowConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(CasConfigurationProperties.class)
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
        @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_DEVICE_PROVIDER)
        public MultifactorAuthenticationDeviceProviderAction inalogyAccountDeviceProviderAction(
                @Qualifier("inalogyAuthenticatorDeviceManager")
                final MultifactorAuthenticationDeviceManager inalogyAuthenticatorDeviceManager) {
            return new DefaultMultifactorAuthenticationDeviceProviderAction(inalogyAuthenticatorDeviceManager);
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_PREPARE)
        public Action inalogyAccountProfilePrepareAction(
                final ConfigurableApplicationContext applicationContext,
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider,
                final CasConfigurationProperties casProperties,
                @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
                final OneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry) {
            return WebflowActionBeanSupplier.builder()
                    .withApplicationContext(applicationContext)
                    .withProperties(casProperties)
                    .withAction(() -> new InalogyMultifactorAuthenticationAccountProfilePrepareAction(inalogyAuthenticatorAccountRegistry,
                            inalogyAuthenticatorMultifactorAuthenticationProvider, casProperties))
                    .withId(CasWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_PREPARE)
                    .build()
                    .get();
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = CasWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_REGISTRATION)
        public Action inalogyAccountProfileRegistrationAction(
                final ConfigurableApplicationContext applicationContext,
                final CasConfigurationProperties casProperties,
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider) {
            return WebflowActionBeanSupplier.builder()
                    .withApplicationContext(applicationContext)
                    .withProperties(casProperties)
                    .withAction(() -> new InalogyMultifactorAuthenticationAccountProfileRegistrationAction(inalogyAuthenticatorMultifactorAuthenticationProvider))
                    .withId(CasWebflowConstants.ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_REGISTRATION)
                    .build()
                    .get();
        }

    }
}
