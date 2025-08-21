package cz.ami.cas.inauth.web.flow.action;

import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import cz.ami.cas.inauth.hazelcast.registration.RegistrationRequestMap;
import cz.ami.cas.inauth.web.flow.InalogyWebflowConstants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.web.flow.OneTimeTokenAccountCreateRegistrationAction;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.web.flow.actions.BaseCasWebflowAction;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Slf4j
@RequiredArgsConstructor
public class InalogyAuthenticatorSaveRegistrationAction extends BaseCasWebflowAction {
    /**
     * Parameter name indicating token.
     */
    public static final String REQUEST_PARAMETER_TOKEN = "token";

    /**
     * Parameter name indicating account name.
     */
    public static final String REQUEST_PARAMETER_ACCOUNT_NAME = "accountName";

    /**
     * Parameter name indicating a validation mfa event.
     */
    public static final String REQUEST_PARAMETER_VALIDATE = "validate";

    private final RegistrationRequestMap registrationRequestMap;

    private final OneTimeTokenCredentialRepository repository;

    private final CoreInalogyMultifactorProperties mfaProperties;

    protected OneTimeTokenAccount buildBaseOneTimeTokenAccount(final RequestContext requestContext) {
        val currentAcct = getCandidateAccountFrom(requestContext);
        val accountName = WebUtils.getRequestParameterOrAttribute(requestContext, REQUEST_PARAMETER_ACCOUNT_NAME).orElseThrow();
        return OneTimeTokenAccount.builder()
                .username(currentAcct.getUsername())
                .secretKey(currentAcct.getSecretKey())
                .validationCode(currentAcct.getValidationCode())
                .scratchCodes(currentAcct.getScratchCodes())
                .name(accountName)
                .build();
    }

    protected OneTimeTokenAccount getCandidateAccountFrom(final RequestContext requestContext) {
        return requestContext.getFlowScope()
                .get(OneTimeTokenAccountCreateRegistrationAction.FLOW_SCOPE_ATTR_ACCOUNT, OneTimeTokenAccount.class);
    }

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) {
        try {
            var currentAcct = getCandidateAccountFrom(requestContext);
            val requestId = requestContext.getFlowScope().get("regRequestId", String.class);
            val account = registrationRequestMap.getRequest(requestId);
            if (account == null) {
                LOGGER.error("Account with id [{}] and username [{}] is not found in registration context.", currentAcct.getId(), currentAcct.getUsername());
                return getErrorEvent(requestContext);
            }
            val deviceRegistrationEnabled = MultifactorAuthenticationWebflowUtils.isMultifactorDeviceRegistrationEnabled(requestContext);
            if (!deviceRegistrationEnabled) {
                LOGGER.warn("Device registration is disabled for [{}]", account.getUsername());
                return getErrorEvent(requestContext);
            }

            if (!mfaProperties.isMultipleDeviceRegistrationEnabled()
                    && repository.count(account.getUsername()) > 0) {
                LOGGER.warn("Unable to register multiple devices for [{}]", account.getUsername());
                return getErrorEvent(requestContext);
            }

            val validate = requestContext.getRequestParameters().getBoolean(REQUEST_PARAMETER_VALIDATE);

            val regState = account.getStatus();

            switch (regState) {
                case PENDING -> {
                    LOGGER.debug("Waiting for account [{}] being registered", account.getUsername());
                    return result(InalogyWebflowConstants.TRANSITION_ID_WAIT);
                }
                case REGISTERED -> {
                    if (validate == null || !validate) {
                        val finalAcc = InalogyAuthenticatorAccount.from(account);
                        LOGGER.debug("Storing account [{}]", account);
                        registrationRequestMap.removeRequest(account.getRequestId());
                        MultifactorAuthenticationWebflowUtils.putOneTimeTokenAccount(requestContext, repository.save(finalAcc));
                    }
                    return success();
                }
            }
        } catch (final Exception e) {
            LoggingUtils.error(LOGGER, e);
        }
        return getErrorEvent(requestContext);
    }

    protected Event getErrorEvent(final RequestContext requestContext) {
        val response = WebUtils.getHttpServletResponseFromExternalWebflowContext(requestContext);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        return error();
    }

    protected InalogyAuthenticatorAccount buildOneTimeTokenAccount(final RequestContext requestContext) {
        val acct = buildBaseOneTimeTokenAccount(requestContext);
        return InalogyAuthenticatorAccount.from(acct);
    }
}
