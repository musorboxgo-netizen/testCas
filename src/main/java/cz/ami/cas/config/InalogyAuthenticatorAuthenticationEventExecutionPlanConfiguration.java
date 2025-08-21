package cz.ami.cas.config;

import cz.ami.cas.inauth.InalogyAuthenticatorAuthenticationHandler;
import cz.ami.cas.inauth.InalogyAuthenticatorMultifactorAuthenticationProvider;
import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import cz.ami.cas.inauth.credential.repository.InalogyOneTimeTokenCredentialRepository;
import cz.ami.cas.inauth.credential.repository.JsonInalogyAuthenticatorTokenCredentialRepository;
import cz.ami.cas.inauth.hazelcast.mfa.MfaRequestMap;
import cz.ami.cas.inauth.hazelcast.registration.RegistrationRequestMap;
import cz.ami.cas.inauth.service.InalogyAuthenticatorService;
import cz.ami.cas.inauth.service.InalogyMessagingService;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
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
import org.apereo.cas.otp.repository.credentials.*;
import org.apereo.cas.otp.repository.token.OneTimeTokenRepository;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.util.cipher.CipherExecutorUtils;
import org.apereo.cas.util.cipher.JasyptNumberCipherExecutor;
import org.apereo.cas.util.crypto.CipherExecutor;
import org.apereo.cas.util.spring.beans.BeanCondition;
import org.apereo.cas.util.spring.beans.BeanSupplier;
import org.apereo.cas.util.thread.Cleanable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.ScopedProxyMode;

@EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
@Slf4j
@Configuration(value = "InalogyAuthenticatorAuthenticationEventExecutionPlanConfiguration", proxyBeanMethods = false)
public class InalogyAuthenticatorAuthenticationEventExecutionPlanConfiguration {

    @Configuration(value = "InalogyAuthenticatorAuthenticationEventExecutionPlanHandlerConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
    static class InalogyAuthenticatorAuthenticationEventExecutionPlanHandlerConfiguration {
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorAuthenticationHandler")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public AuthenticationHandler inalogyAuthenticatorAuthenticationHandler(
                @Qualifier("inalogyAuthenticatorMultifactorAuthenticationProvider")
                final ObjectProvider<MultifactorAuthenticationProvider> multifactorAuthenticationProvider,
                final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
                @Qualifier("inalogyPrincipalFactory")
                final PrincipalFactory inalogyPrincipalFactory,
                @Qualifier("inalogyAuthenticatorOneTimeTokenCredentialValidator")
                final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> inalogyAuthenticatorOneTimeTokenCredentialValidator,
                @Qualifier(ServicesManager.BEAN_NAME)
                final ServicesManager servicesManager) {
            return new InalogyAuthenticatorAuthenticationHandler(inalogyMfaProperties.getName(), servicesManager,
                    inalogyPrincipalFactory, inalogyAuthenticatorOneTimeTokenCredentialValidator,
                    inalogyMfaProperties.getOrder(), multifactorAuthenticationProvider);
        }

    }

    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationCoreConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
    static class InalogyAuthenticatorMultifactorAuthenticationCoreConfiguration {
        private static final BeanCondition CONDITION_SCRATCH_CODE =
                BeanCondition.on("cas.authn.mfa.inalogy.core.scratch-codes.encryption.key");

        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @Bean
        @ConditionalOnMissingBean(name = "inalogyMessagingService")
        public InalogyMessagingService inalogyMessagingService(final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
            val messagingService = inalogyMfaProperties.getMessagingService();
            return new InalogyMessagingService(messagingService);
        }

        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @Bean
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorInstance")
        public IInalogyAuthenticator inalogyAuthenticatorInstance(
                final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
                @Qualifier(BaseInalogyAuthenticatorTokenCredentialRepository.BEAN_NAME)
                final InalogyOneTimeTokenCredentialRepository credentialRepository,
                @Qualifier("inalogyMessagingService")
                final InalogyMessagingService messagingService,
                @Qualifier(MfaRequestMap.BEAN_NAME)
                final MfaRequestMap mfaRequestMap,
                @Qualifier(RegistrationRequestMap.BEAN_NAME)
                final RegistrationRequestMap registrationRequestMap
                ) {
            return new InalogyAuthenticatorService(inalogyMfaProperties.getCore(), credentialRepository, messagingService,
                    mfaRequestMap, registrationRequestMap);
        }

        @ConditionalOnMissingBean(name = "inalogyAuthenticatorAccountCipherExecutor")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public CipherExecutor inalogyAuthenticatorAccountCipherExecutor(final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
            val crypto = inalogyMfaProperties.getCrypto();
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
                                                                            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
            return BeanSupplier.of(CipherExecutor.class)
                    .when(CONDITION_SCRATCH_CODE.given(applicationContext.getEnvironment()))
                    .supply(() -> {
                        val key = inalogyMfaProperties.getCore().getScratchCodes().getEncryption().getKey();
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
    @EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
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

    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationPlanConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
    static class InalogyAuthenticatorMultifactorAuthenticationPlanConfiguration {
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorAuthenticationEventExecutionPlanConfigurer")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public AuthenticationEventExecutionPlanConfigurer inalogyAuthenticatorAuthenticationEventExecutionPlanConfigurer(
                @Qualifier("inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator")
                final AuthenticationMetaDataPopulator inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator,
                final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
                @Qualifier("inalogyAuthenticatorAuthenticationHandler")
                final AuthenticationHandler inalogyAuthenticatorAuthenticationHandler,
                @Qualifier("inalogyAuthenticatorAuthenticationMetaDataPopulator")
                final AuthenticationMetaDataPopulator inalogyAuthenticatorAuthenticationMetaDataPopulator) {
            return plan -> {
                if (StringUtils.isNotBlank(inalogyMfaProperties.getCore().getIssuer())) {
                    plan.registerAuthenticationHandler(inalogyAuthenticatorAuthenticationHandler);
                    plan.registerAuthenticationMetadataPopulator(inalogyAuthenticatorAuthenticationMetaDataPopulator);
                    plan.registerAuthenticationMetadataPopulator(inalogyAuthenticatorMultifactorProviderAuthenticationMetadataPopulator);
                    plan.registerAuthenticationHandlerResolver(new ByCredentialTypeAuthenticationHandlerResolver(InalogyAuthenticatorTokenCredential.class));
                }
            };
        }
    }
    
    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationTokenConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
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
        public InalogyOneTimeTokenCredentialRepository inalogyAuthenticatorAccountRegistry(
                final ConfigurableApplicationContext applicationContext,
                final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
                @Lazy @Qualifier("inalogyAuthenticatorInstance")
                final IInalogyAuthenticator inalogyAuthenticatorInstance,
                @Qualifier("inalogyAuthenticatorAccountCipherExecutor")
                final CipherExecutor inalogyAuthenticatorAccountCipherExecutor,
                @Qualifier("inalogyAuthenticatorScratchCodesCipherExecutor")
                final CipherExecutor inalogyAuthenticatorScratchCodesCipherExecutor) {
            if (inalogyMfaProperties.getJson().getLocation() != null) {
                return new JsonInalogyAuthenticatorTokenCredentialRepository(inalogyMfaProperties.getJson().getLocation(),
                        inalogyAuthenticatorInstance, inalogyAuthenticatorAccountCipherExecutor,
                        inalogyAuthenticatorScratchCodesCipherExecutor,
                        new OneTimeTokenAccountSerializer(applicationContext));
            }
            return new InMemoryInalogyAuthenticatorTokenCredentialRepository(
                    inalogyAuthenticatorAccountCipherExecutor, inalogyAuthenticatorScratchCodesCipherExecutor, inalogyAuthenticatorInstance);
        }
    }
    
    @Configuration(value = "InalogyAuthenticatorMultifactorAuthenticationProviderConfiguration", proxyBeanMethods = false)
    @EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
    static class InalogyAuthenticatorMultifactorAuthenticationProviderConfiguration {
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        @ConditionalOnMissingBean(name = "inalogyAuthenticatorMultifactorAuthenticationProvider")
        public MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider(
                final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
                @Qualifier("inalogyAuthenticatorBypassEvaluator")
                final MultifactorAuthenticationProviderBypassEvaluator inalogyAuthenticatorBypassEvaluator,
                @Qualifier("failureModeEvaluator")
                final MultifactorAuthenticationFailureModeEvaluator failureModeEvaluator,
                @Qualifier("inalogyAuthenticatorDeviceManager")
                final MultifactorAuthenticationDeviceManager inalogyAuthenticatorDeviceManager) {
            val provider = new InalogyAuthenticatorMultifactorAuthenticationProvider();
            provider.setBypassEvaluator(inalogyAuthenticatorBypassEvaluator);
            provider.setFailureMode(inalogyMfaProperties.getFailureMode());
            provider.setFailureModeEvaluator(failureModeEvaluator);
            provider.setOrder(inalogyMfaProperties.getRank());
            provider.setId(inalogyMfaProperties.getId());
            provider.setDeviceManager(inalogyAuthenticatorDeviceManager);
            return provider;
        }
    }

}
