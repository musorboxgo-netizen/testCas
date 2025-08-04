package cz.ami.cas.inauth.web.flow;

import cz.ami.cas.inauth.authenticator.repository.TemporaryAccountStorage;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import cz.ami.cas.inauth.token.InalogyAuthenticatorToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialValidator;
import org.apereo.cas.otp.web.flow.OneTimeTokenAccountCreateRegistrationAction;
import org.apereo.cas.util.LoggingUtils;
import org.apereo.cas.web.flow.actions.BaseCasWebflowAction;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.Objects;

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
     * Parameter name indicating a validation request event.
     */
    public static final String REQUEST_PARAMETER_VALIDATE = "validate";

    private final TemporaryAccountStorage temporaryAccountStorage;

    private final OneTimeTokenCredentialRepository repository;

    private final CasConfigurationProperties casProperties;

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

    protected InalogyAuthenticatorAccount getCandidateAccountFrom(final RequestContext requestContext) {
        return (InalogyAuthenticatorAccount) requestContext.getFlowScope()
                .get(OneTimeTokenAccountCreateRegistrationAction.FLOW_SCOPE_ATTR_ACCOUNT, OneTimeTokenAccount.class);
    }

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) {
        try {
            val currentAcct = getCandidateAccountFrom(requestContext);
            val deviceRegistrationEnabled = MultifactorAuthenticationWebflowUtils.isMultifactorDeviceRegistrationEnabled(requestContext);
            if (!deviceRegistrationEnabled) {
                LOGGER.warn("Device registration is disabled for [{}]", currentAcct.getUsername());
                return getErrorEvent(requestContext);
            }

            if (!casProperties.getAuthn().getMfa().getInalogy().getCore().isMultipleDeviceRegistrationEnabled()
                    && repository.count(currentAcct.getUsername()) > 0) {
                LOGGER.warn("Unable to register multiple devices for [{}]", currentAcct.getUsername());
                return getErrorEvent(requestContext);
            }
            val accountOpt = temporaryAccountStorage.findById(currentAcct.getId());
            if (accountOpt.isEmpty()) {
                LOGGER.error("Account with id [{}] and username [{}] is not found in registration context", currentAcct.getId(), currentAcct.getUsername());
                return getErrorEvent(requestContext);
            }

            val account = accountOpt.get();

            account.setName(WebUtils.getRequestParameterOrAttribute(requestContext, REQUEST_PARAMETER_ACCOUNT_NAME).orElseThrow());

            val validate = requestContext.getRequestParameters().getBoolean(REQUEST_PARAMETER_VALIDATE);

            val regState = temporaryAccountStorage.getRegistrationStatus(currentAcct.getId());

            switch (regState) {
                case TemporaryAccountStorage.STATUS_WAITING -> {
                    LOGGER.debug("Waiting for account [{}] being registered", account.getUsername());
                    return result("waiting");
                }
                case TemporaryAccountStorage.STATUS_REJECTED -> {
                    LOGGER.error("Unable to register device for [{}]", currentAcct.getUsername());
                    temporaryAccountStorage.removeAccount(account.getId());
                    requestContext.getFlowScope().put("registrationError", "The verification code is invalid or has expired. Please try again.");
                    return getErrorEvent(requestContext);
                }
                case TemporaryAccountStorage.STATUS_REGISTERED -> {
                    if (validate == null || !validate) {
                        LOGGER.debug("Storing account [{}]", account);
                        MultifactorAuthenticationWebflowUtils.putOneTimeTokenAccount(requestContext, repository.save(account));
                    }
                    temporaryAccountStorage.removeAccount(account.getId());
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
