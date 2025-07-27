package cz.ami.cas.inauth.web.flow;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.gauth.credential.GoogleAuthenticatorTokenCredential;
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
            createFlowVariable(flow, CasWebflowConstants.VAR_ID_CREDENTIAL, InalogyAuthenticatorTokenCredential.class);

            flow.getStartActionList().add(createEvaluateAction(CasWebflowConstants.ACTION_ID_INITIAL_FLOW_SETUP));
            createEndState(flow, CasWebflowConstants.STATE_ID_SUCCESS);

            // Create the initial login form state
            val initLoginFormState = createActionState(flow, CasWebflowConstants.STATE_ID_INIT_LOGIN_FORM,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_PREPARE_LOGIN),
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INIT_LOGIN_ACTION));
            createTransitionForState(initLoginFormState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);
            setStartState(flow, initLoginFormState);

            val acctRegCheckState = createActionState(flow, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION));
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_REGISTER, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION);
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_CONFIRM, "viewConfirmRegistration");
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_SUCCESS, "initPushAuthentication");
            createTransitionForState(acctRegCheckState, CasWebflowConstants.TRANSITION_ID_STOP, CasWebflowConstants.STATE_ID_REGISTRATION_REQUIRED);

            createViewState(flow, CasWebflowConstants.STATE_ID_REGISTRATION_REQUIRED, "inauth/casInalogyAuthenticatorRegistrationRequiredView");

            val acctRegStatusCheckState = createActionState(flow, "checkAccountRegStatusState");

            acctRegStatusCheckState.getActionList().add(createEvaluateAction("inalogyCheckAccountRegStatusAction"));

//            createTransitionForState(acctRegStatusCheckState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_INALOGY_SAVE_REGISTRATION);
            createTransitionForState(acctRegStatusCheckState, "stop", CasWebflowConstants.STATE_ID_INIT_LOGIN_FORM);
            createTransitionForState(acctRegStatusCheckState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_SUCCESS);
            createTransitionForState(acctRegStatusCheckState, "waiting", "checkAccountRegStatusState");

            val acctRegSaveState = createActionState(flow, CasWebflowConstants.STATE_ID_INALOGY_SAVE_REGISTRATION,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION));
            createTransitionForState(acctRegSaveState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);
            createStateDefaultTransition(acctRegSaveState, CasWebflowConstants.STATE_ID_CHECK_ACCOUNT_REGISTRATION);

            // Create the real submit state for handling form submission
            val realSubmitState = createActionState(flow, CasWebflowConstants.STATE_ID_REAL_SUBMIT,
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION),
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_OTP_AUTHENTICATION_ACTION));
            createTransitionForState(realSubmitState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_SUCCESS);
            createTransitionForState(realSubmitState, CasWebflowConstants.TRANSITION_ID_ERROR, "viewRegistration");

            // Create the registration view state that will display the QR code
            val setPrincipalAction = createSetAction("viewScope.principal", "conversationScope.authentication.principal");

            // Create a proper binding for the token credential
            val propertiesToBindLogin = CollectionUtils.wrapList("token", "accountId");
            val propertiesToBindRegister = CollectionUtils.wrapList("accountId");
            val regBinder = createStateBinderConfiguration(propertiesToBindRegister);
            val loginBinder = createStateBinderConfiguration(propertiesToBindLogin);
            val inalogyLoginFormState = createViewState(flow, CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM, "inauth/casInalogyAuthenticatorLoginView", loginBinder);
            createStateModelBinding(inalogyLoginFormState, CasWebflowConstants.VAR_ID_CREDENTIAL, InalogyAuthenticatorTokenCredential.class);
            inalogyLoginFormState.getEntryActionList().add(setPrincipalAction);

            createTransitionForState(inalogyLoginFormState, CasWebflowConstants.TRANSITION_ID_SUBMIT,
                    CasWebflowConstants.STATE_ID_REAL_SUBMIT, Map.of("bind", Boolean.TRUE, "validate", Boolean.TRUE));

            createTransitionForState(inalogyLoginFormState, CasWebflowConstants.TRANSITION_ID_REGISTER, CasWebflowConstants.STATE_ID_VIEW_REGISTRATION,
                    Map.of("bind", Boolean.FALSE, "validate", Boolean.FALSE));

            createTransitionForState(inalogyLoginFormState, CasWebflowConstants.TRANSITION_ID_CONFIRM, "validateInalogyAccountToken",
                    Map.of("bind", Boolean.FALSE, "validate", Boolean.FALSE));

            createTransitionForState(inalogyLoginFormState, CasWebflowConstants.TRANSITION_ID_SELECT, "viewConfirmRegistration",
                    Map.of("bind", Boolean.FALSE, "validate", Boolean.FALSE));

            // ДОБАВЛЯЕМ НОВЫЙ ПЕРЕХОД ДЛЯ PUSH-АУТЕНТИФИКАЦИИ
            createTransitionForState(inalogyLoginFormState, "pushAuth", "initPushAuthentication",
                    Map.of("bind", Boolean.FALSE, "validate", Boolean.FALSE));

            val regViewState = createViewState(flow, "viewRegistration", "inauth/casInalogyAuthenticatorRegistrationView", regBinder);
            createStateModelBinding(regViewState, CasWebflowConstants.VAR_ID_CREDENTIAL, InalogyAuthenticatorTokenCredential.class);
            regViewState.getEntryActionList().addAll(setPrincipalAction, createEvaluateAction("inalogyAccountCreateRegistrationAction"));
            createTransitionForState(regViewState, CasWebflowConstants.TRANSITION_ID_SUBMIT, "checkAccountRegStatusState" /*CasWebflowConstants.STATE_ID_INALOGY_SAVE_REGISTRATION*/);
            createTransitionForState(regViewState, "checkStatus", "checkAccountRegStatusState");

            val confirmTokenState = createActionState(flow, "validateInalogyAccountToken", CasWebflowConstants.ACTION_ID_INALOGY_VALIDATE_TOKEN);
            createTransitionForState(confirmTokenState, CasWebflowConstants.TRANSITION_ID_SUCCESS, regViewState.getId());
            createTransitionForState(confirmTokenState, CasWebflowConstants.TRANSITION_ID_ERROR, inalogyLoginFormState.getId());

            // ДОБАВЛЯЕМ НОВЫЕ СОСТОЯНИЯ ДЛЯ PUSH-АУТЕНТИФИКАЦИИ

            // 1. Состояние инициализации push-аутентификации
            val pushInitState = createActionState(flow, "initPushAuthentication",
                    createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_PUSH_INIT));
            createTransitionForState(pushInitState, CasWebflowConstants.TRANSITION_ID_SUCCESS, "waitForPushResponse");
            createTransitionForState(pushInitState, "deviceNotRegistered", CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);

            // 2. Состояние ожидания ответа на push-аутентификацию
            val waitForPushState = createViewState(flow, "waitForPushResponse", "inauth/casInalogyPushWaitView");
            waitForPushState.getEntryActionList().add(createEvaluateAction(CasWebflowConstants.ACTION_ID_INALOGY_CHECK_RESPONSE));

            // 3. Создаем переходы для состояния ожидания
            createTransitionForState(waitForPushState, CasWebflowConstants.TRANSITION_ID_SUCCESS, CasWebflowConstants.STATE_ID_SUCCESS);
            createTransitionForState(waitForPushState, "rejected", CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);
            createTransitionForState(waitForPushState, "timeout", CasWebflowConstants.STATE_ID_VIEW_LOGIN_FORM);
            createTransitionForState(waitForPushState, "waiting", "waitForPushResponse");
        });

        registerMultifactorProviderAuthenticationWebflow(getLoginFlow(), providerId, providerId);
    }
}
