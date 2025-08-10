package cz.ami.cas.inauth.web.flow;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.configurer.AbstractCasMultifactorWebflowConfigurer;
import org.apereo.cas.web.flow.configurer.CasMultifactorWebflowCustomizer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.Flow;
import org.springframework.webflow.engine.State;
import org.springframework.webflow.engine.TransitionableState;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * This is {@link InalogyAuthenticatorMultifactorWebflowConfigurer}.
 * Configures the webflow for Inalogy Authenticator MFA.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Slf4j
public class InalogyAuthenticatorMultifactorWebflowConfigurer extends AbstractCasMultifactorWebflowConfigurer {

    public InalogyAuthenticatorMultifactorWebflowConfigurer(final FlowBuilderServices flowBuilderServices,
                                                           final FlowDefinitionRegistry flowDefinitionRegistry,
                                                           final FlowDefinitionRegistry mfaFlowDefinitionRegistry,
                                                           final ConfigurableApplicationContext applicationContext,
                                                           final CasConfigurationProperties casProperties,
                                                           final List<CasMultifactorWebflowCustomizer> mfaFlowCustomizers) {
        super(flowBuilderServices, flowDefinitionRegistry,
            applicationContext, casProperties, Optional.of(mfaFlowDefinitionRegistry),
            mfaFlowCustomizers);
    }

    @Override
    protected void doInitialize() {
        val providerId = casProperties.getAuthn().getMfa().getInalogy().getId();
        LOGGER.info("Configuring Inalogy Authenticator MFA webflow with provider ID: [{}]", providerId);

        // Configure the MFA provider flow
        multifactorAuthenticationFlowDefinitionRegistries.forEach(registry -> {
            val flow = getFlow(registry, providerId);


            flow.getStartActionList().add(createEvaluateAction(CasWebflowConstants.ACTION_ID_INITIAL_FLOW_SETUP));
            createEndState(flow, CasWebflowConstants.STATE_ID_SUCCESS);

            val initLoginFormState = createActionState(flow, CasWebflowConstants.STATE_ID_INIT_LOGIN_FORM,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_PREPARE_LOGIN),
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INIT_LOGIN_ACTION));
            createTransitionForState(initLoginFormState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);
            setStartState(flow, initLoginFormState);

            val acctRegCheckState = createActionState(flow, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION));
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_REGISTER, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION);
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_CONFIRM, "viewConfirmRegistration");
//            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_SUCCESS);
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_STOP, CasWebflowConstants.STATE_ID_REGISTRATION_REQUIRED);
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_SUCCESS, "initMfaWebflow");

            createViewState(flow, CasWebflowConstants.STATE_ID_REGISTRATION_REQUIRED, "inauth/casInalogyAuthenticatorRegistrationRequiredView");

            val acctRegSaveState = createActionState(flow, CasWebflowConstants.STATE_ID_INALOGY_SAVE_REGISTRATION,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION));
            createTransitionForState(acctRegSaveState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);
            createStateDefaultTransition(acctRegSaveState, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);

            val realSubmitState = createActionState(flow, CasWebflowConstants.STATE_ID_REAL_SUBMIT,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION),
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_OTP_AUTHENTICATION_ACTION));
            createTransitionForState(realSubmitState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_SUCCESS);
            createTransitionForState(realSubmitState, CasWebflowConstants.TRANSITION_ID_ERROR, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);

            val setPrincipalAction = createSetAction("viewScope.principal", "conversationScope.authentication.principal");

            val inalogyLoginFormState = createViewState(flow, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM,
                    "inauth/casInalogyAuthenticatorLoginView");
            inalogyLoginFormState.getEntryActionList().add(createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE));
            createTransitionForState(inalogyLoginFormState, CasWebflowConstants.TRANSITION_ID_SUBMIT, CasWebflowConstants.STATE_ID_SUCCESS);
            createTransitionForState(inalogyLoginFormState, "waiting", CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);
            createTransitionForState(inalogyLoginFormState, "rejected", "viewLoginError");
            createTransitionForState(inalogyLoginFormState, "timeout", "viewLoginError");

            val regViewState = createViewState(flow, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION, "inauth/casInalogyAuthenticatorRegistrationView");
            regViewState.getEntryActionList().addAll(setPrincipalAction, createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_ACCOUNT_CREATE_REGISTRATION));
            createTransitionForState(regViewState, CasWebflowConstants.TRANSITION_ID_SUBMIT, CasWebflowConstants.STATE_ID_INALOGY_SAVE_REGISTRATION);

            // 1. State to initialize MFA webflow by sending mfa through messaging service
            val initMfaWebflowState = createActionState(flow, "initMfaWebflow",
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_PUSH_INIT));
            createTransitionForState(initMfaWebflowState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);
            createTransitionForState(initMfaWebflowState, "deviceNotRegistered", "viewLoginError");
            createTransitionForState(initMfaWebflowState, CasWebflowConstants.TRANSITION_ID_ERROR, "viewLoginError");

            // 6. Error view state
            createViewState(flow, "viewLoginError", "inauth/casInalogyAuthenticatorLoginErrorView");
        });

        registerMultifactorProviderAuthenticationWebflow(getLoginFlow(), providerId, providerId);
    }
}
