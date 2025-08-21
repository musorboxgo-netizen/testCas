package cz.ami.cas.config;

import com.hazelcast.core.HazelcastInstance;
import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import cz.ami.cas.inauth.hazelcast.mfa.InalogyMfaRequestHazelcastMap;
import cz.ami.cas.inauth.hazelcast.mfa.MfaRequestMap;
import cz.ami.cas.inauth.hazelcast.registration.InalogyRegRequestHazelcastMap;
import cz.ami.cas.inauth.hazelcast.registration.RegistrationRequestMap;
import cz.ami.cas.inauth.web.flow.InalogyAuthenticatorMultifactorWebflowConfigurer;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.CasWebflowExecutionPlanConfigurer;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.webflow.config.FlowDefinitionRegistryBuilder;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.FlowBuilder;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;

@EnableConfigurationProperties(InalogyAuthenticatorMultifactorProperties.class)
@EnableScheduling
@Configuration(value = "InalogyAuthenticatorConfiguration", proxyBeanMethods = false)
public class InalogyAuthenticatorConfiguration {

    private static final int WEBFLOW_CONFIGURER_ORDER = 101;

    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    @ConditionalOnMissingBean(name = "inalogyAuthenticatorFlowRegistry")
    public FlowDefinitionRegistry inalogyAuthenticatorFlowRegistry(
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
            final ConfigurableApplicationContext applicationContext,
            @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER_SERVICES)
            final FlowBuilderServices flowBuilderServices,
            @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER)
            final FlowBuilder flowBuilder) {
        val builder = new FlowDefinitionRegistryBuilder(applicationContext, flowBuilderServices);
        builder.addFlowBuilder(flowBuilder, inalogyMfaProperties.getId());
        return builder.build();
    }

    @ConditionalOnMissingBean(name = "inalogyAuthenticatorMultifactorWebflowConfigurer")
    @Bean
    @RefreshScope(proxyMode = ScopedProxyMode.DEFAULT)
    public CasWebflowConfigurer inalogyAuthenticatorMultifactorWebflowConfigurer(
            final CasConfigurationProperties casProperties,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties,
            final ConfigurableApplicationContext applicationContext,
            @Qualifier("inalogyAuthenticatorFlowRegistry")
            final FlowDefinitionRegistry inalogyAuthenticatorFlowRegistry,
            @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_DEFINITION_REGISTRY)
            final FlowDefinitionRegistry flowDefinitionRegistry,
            @Qualifier(CasWebflowConstants.BEAN_NAME_FLOW_BUILDER_SERVICES)
            final FlowBuilderServices flowBuilderServices) {
        val cfg = new InalogyAuthenticatorMultifactorWebflowConfigurer(flowBuilderServices,
                flowDefinitionRegistry, inalogyAuthenticatorFlowRegistry, applicationContext, casProperties, inalogyMfaProperties,
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

    @Bean( MfaRequestMap.BEAN_NAME)
    @RefreshScope
    @ConditionalOnMissingBean(name = InalogyMfaRequestHazelcastMap.BEAN_NAME)
    public MfaRequestMap inalogyMfaRequestMap(
            @Qualifier("casTicketRegistryHazelcastInstance")
            final ObjectProvider<HazelcastInstance> casTicketRegistryHazelcastInstance,
            final CasConfigurationProperties casProperties,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        return new InalogyMfaRequestHazelcastMap(casTicketRegistryHazelcastInstance.getObject(), casProperties, inalogyMfaProperties.getCore());
    }

    @Bean( RegistrationRequestMap.BEAN_NAME)
    @RefreshScope
    @ConditionalOnMissingBean(name = InalogyRegRequestHazelcastMap.BEAN_NAME)
    public RegistrationRequestMap inalogyRegRequestMap(
            @Qualifier("casTicketRegistryHazelcastInstance")
            final ObjectProvider<HazelcastInstance> casTicketRegistryHazelcastInstance,
            final CasConfigurationProperties casProperties,
            final InalogyAuthenticatorMultifactorProperties inalogyMfaProperties) {
        return new InalogyRegRequestHazelcastMap(casTicketRegistryHazelcastInstance.getObject(), casProperties, inalogyMfaProperties.getCore());
    }
}
