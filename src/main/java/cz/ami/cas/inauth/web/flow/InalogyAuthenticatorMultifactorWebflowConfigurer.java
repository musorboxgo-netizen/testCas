package cz.ami.cas.inauth.web.flow;

import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.configurer.AbstractCasMultifactorWebflowConfigurer;
import org.apereo.cas.web.flow.configurer.CasMultifactorWebflowCustomizer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;

import java.util.List;
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

    private final InalogyAuthenticatorMultifactorProperties mfaProperties;

    public InalogyAuthenticatorMultifactorWebflowConfigurer(final FlowBuilderServices flowBuilderServices,
                                                            final FlowDefinitionRegistry flowDefinitionRegistry,
                                                            final FlowDefinitionRegistry mfaFlowDefinitionRegistry,
                                                            final ConfigurableApplicationContext applicationContext,
                                                            final CasConfigurationProperties casProperties,
                                                            final InalogyAuthenticatorMultifactorProperties mfaProperties,
                                                           final List<CasMultifactorWebflowCustomizer> mfaFlowCustomizers) {
        super(flowBuilderServices, flowDefinitionRegistry,
            applicationContext, casProperties, Optional.of(mfaFlowDefinitionRegistry),
            mfaFlowCustomizers);
        this.mfaProperties = mfaProperties;
    }

    @Override
    protected void doInitialize() {
        val providerId = mfaProperties.getId();
        LOGGER.info("Configuring Inalogy Authenticator MFA webflow with provider ID: [{}]", providerId);

        // Configure the MFA provider flow
        multifactorAuthenticationFlowDefinitionRegistries.forEach(registry -> {
            val flow = getFlow(registry, providerId);
            createFlowVariable(flow, CasWebflowConstants.VAR_ID_CREDENTIAL, InalogyAuthenticatorTokenCredential.class);

            flow.getStartActionList().add(createEvaluateAction(CasWebflowConstants.ACTION_ID_INITIAL_FLOW_SETUP));
            createEndState(flow, CasWebflowConstants.STATE_ID_SUCCESS);

            val initLoginFormState = createActionState(flow, CasWebflowConstants.STATE_ID_INIT_LOGIN_FORM,
                    createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_PREPARE_LOGIN),
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INIT_LOGIN_ACTION));
            createTransitionForState(initLoginFormState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);
            setStartState(flow, initLoginFormState);

            val acctRegCheckState = createActionState(flow, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION,
                    createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION));
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_REGISTER, InalogyWebflowConstants.STATE_ID_INALOGY_DECIDE_DOWNLOAD);
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_CONFIRM, "viewConfirmRegistration");
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_STOP, CasWebflowConstants.STATE_ID_REGISTRATION_REQUIRED);
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_SUCCESS, InalogyWebflowConstants.STATE_ID_INALOGY_INIT_MFA);

            val downloadViewState = createViewState(flow, InalogyWebflowConstants.STATE_ID_INALOGY_DISPLAY_DOWNLOAD, "inauth/casInalogyAuthenticatorDownloadAppView");
            createTransitionForState(downloadViewState, CasWebflowConstants.TRANSITION_ID_SUBMIT, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION);

            val displayDownloadQrState = createActionState(flow, InalogyWebflowConstants.STATE_ID_INALOGY_DECIDE_DOWNLOAD,
                    createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_DECIDE_DOWNLOAD));
            createTransitionForState(displayDownloadQrState, InalogyWebflowConstants.TRANSITION_ID_DISPLAY, downloadViewState.getId());
            createTransitionForState(displayDownloadQrState, CasWebflowConstants.TRANSITION_ID_REGISTER, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION);

            createViewState(flow, CasWebflowConstants.STATE_ID_REGISTRATION_REQUIRED, "inauth/casInalogyAuthenticatorRegistrationRequiredView");

            val acctRegSaveState = createActionState(flow, InalogyWebflowConstants.STATE_ID_INALOGY_SAVE_REGISTRATION,
                    createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION));
            createTransitionForState(acctRegSaveState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);
            createTransitionForState(acctRegSaveState, InalogyWebflowConstants.TRANSITION_ID_WAIT, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION);
            createStateDefaultTransition(acctRegSaveState, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);

            val setPrincipalAction = createSetAction("viewScope.principal", "conversationScope.authentication.principal");

            val realSubmitState = createActionState(flow, CasWebflowConstants.STATE_ID_REAL_SUBMIT,
                    createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION),
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_OTP_AUTHENTICATION_ACTION));
            createTransitionForState(realSubmitState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_SUCCESS);
            createTransitionForState(realSubmitState, CasWebflowConstants.TRANSITION_ID_ERROR, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);

            val confirmRegViewState = createViewState(flow, "viewConfirmRegistration", "gauth/casInalogyAuthenticatorConfirmRegistrationView");
            confirmRegViewState.getEntryActionList().add(setPrincipalAction);
            confirmRegViewState.getEntryActionList().add(createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_PREPARE_LOGIN));

            val regViewState = createViewState(flow, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION, "inauth/casInalogyAuthenticatorRegistrationView");
            regViewState.getEntryActionList().addAll(setPrincipalAction, createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_ACCOUNT_CREATE_REGISTRATION));
            createTransitionForState(regViewState, CasWebflowConstants.TRANSITION_ID_SUBMIT, InalogyWebflowConstants.STATE_ID_INALOGY_SAVE_REGISTRATION);

            val initMfaWebflowState = createActionState(flow, InalogyWebflowConstants.STATE_ID_INALOGY_INIT_MFA,
                    createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_PUSH_INIT));
            createTransitionForState(initMfaWebflowState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);
            createTransitionForState(initMfaWebflowState, InalogyWebflowConstants.TRANSITION_ID_DEVICE_NOT_REGISTERED, "viewLoginError");
            createTransitionForState(initMfaWebflowState, CasWebflowConstants.TRANSITION_ID_ERROR, "viewLoginError");

            val inalogyLoginFormState = createViewState(flow, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM,
                    "inauth/casInalogyAuthenticatorLoginView");
            inalogyLoginFormState.getEntryActionList().add(createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE));
            createTransitionForState(inalogyLoginFormState, CasWebflowConstants.TRANSITION_ID_SUBMIT, CasWebflowConstants.STATE_ID_REAL_SUBMIT);
            createTransitionForState(inalogyLoginFormState, InalogyWebflowConstants.TRANSITION_ID_WAIT, InalogyWebflowConstants.STATE_ID_CHECK_PUSH_RESPONSE);
            createTransitionForState(inalogyLoginFormState, InalogyWebflowConstants.TRANSITION_ID_REJECTED, "viewLoginError");
            createTransitionForState(inalogyLoginFormState, InalogyWebflowConstants.TRANSITION_ID_TIMEOUT, "viewLoginError");

            var checkPushState = createActionState(flow, InalogyWebflowConstants.STATE_ID_CHECK_PUSH_RESPONSE,
                    createEvaluateAction(InalogyWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE));
            createTransitionForState(checkPushState, CasWebflowConstants.TRANSITION_ID_SUBMIT, CasWebflowConstants.STATE_ID_REAL_SUBMIT);
            createTransitionForState(checkPushState, InalogyWebflowConstants.TRANSITION_ID_WAIT, InalogyWebflowConstants.STATE_ID_CHECK_PUSH_RESPONSE);
            createTransitionForState(checkPushState, InalogyWebflowConstants.TRANSITION_ID_REJECTED, "viewLoginError");
            createTransitionForState(checkPushState, InalogyWebflowConstants.TRANSITION_ID_TIMEOUT, "viewLoginError");

            createViewState(flow, "viewLoginError", "inauth/casInalogyAuthenticatorLoginErrorView");
        });

        registerMultifactorProviderAuthenticationWebflow(getLoginFlow(), providerId, providerId);
    }
}
