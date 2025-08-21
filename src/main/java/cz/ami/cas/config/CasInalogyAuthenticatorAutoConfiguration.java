package cz.ami.cas.config;

import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.trusted.web.flow.BasicMultifactorTrustedWebflowConfigurer;
import org.apereo.cas.util.spring.beans.BeanCondition;
import org.apereo.cas.util.spring.beans.BeanSupplier;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

@EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
@EnableScheduling
@AutoConfiguration
@Import({
        InalogyAuthenticatorAuthenticationComponentSerializationConfiguration.class,
        InalogyAuthenticatorAuthenticationEventExecutionPlanConfiguration.class,
        InalogyAuthenticatorAuthenticationMultifactorProviderBypassConfiguration.class,
        InalogyAuthenticatorConfiguration.class,
        InalogyAuthenticatorControllerConfiguration.class,
        InalogyAuthenticatorWebflowConfiguration.class
})
@ConditionalOnProperty(prefix = "ami.inalogy.mfa", name = "enabled", havingValue = "true", matchIfMissing = true)
public class CasInalogyAuthenticatorAutoConfiguration {
    @Configuration(value = "InalogyAuthenticatorMultifactorTrustConfiguration", proxyBeanMethods = false)
    @DependsOn("inalogyAuthenticatorMultifactorWebflowConfigurer")
    public static class InalogyAuthenticatorMultifactorTrustConfiguration {
        private static final int WEBFLOW_CONFIGURER_ORDER = 101;

        private static final BeanCondition CONDITION = BeanCondition.on("ami.inalogy.mfa.core.trusted-device-enabled")
                .isTrue().evenIfMissing();

        @ConditionalOnMissingBean(name = "inalogyMultifactorTrustWebflowConfigurer")
        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public CasWebflowConfigurer inalogyMultifactorTrustWebflowConfigurer(
                @Qualifier("inalogyAuthenticatorFlowRegistry")
                final FlowDefinitionRegistry inalogyAuthenticatorFlowRegistry,
                final ConfigurableApplicationContext applicationContext,
                final CasConfigurationProperties casProperties,
                @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_DEFINITION_REGISTRY)
                final FlowDefinitionRegistry flowDefinitionRegistry,
                @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER_SERVICES)
                final FlowBuilderServices flowBuilderServices) {
            return BeanSupplier.of(CasWebflowConfigurer.class)
                    .when(CONDITION.given(applicationContext.getEnvironment()))
                    .supply(() -> {
                        val cfg = new BasicMultifactorTrustedWebflowConfigurer(flowBuilderServices,
                                flowDefinitionRegistry, inalogyAuthenticatorFlowRegistry, applicationContext, casProperties,
                                MultifactorAuthenticationWebflowUtils.getMultifactorAuthenticationWebflowCustomizers(applicationContext));
                        cfg.setOrder(WEBFLOW_CONFIGURER_ORDER + 1);
                        return cfg;
                    })
                    .otherwiseProxy()
                    .get();
        }

        @Bean
        @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
        public CasWebflowExecutionPlanConfigurer inalogyMultifactorTrustCasWebflowExecutionPlanConfigurer(
                final ConfigurableApplicationContext applicationContext,
                @Qualifier("inalogyMultifactorTrustWebflowConfigurer")
                final CasWebflowConfigurer inalogyMultifactorTrustWebflowConfigurer) {
            return BeanSupplier.of(CasWebflowExecutionPlanConfigurer.class)
                    .when(CONDITION.given(applicationContext.getEnvironment()))
                    .supply(() -> plan -> plan.registerWebflowConfigurer(inalogyMultifactorTrustWebflowConfigurer))
                    .otherwiseProxy()
                    .get();
        }
    }
}
