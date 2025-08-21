package cz.ami.cas.inauth.web.flow.action;

import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import cz.ami.cas.inauth.hazelcast.mfa.MfaRequestMap;
import cz.ami.cas.inauth.token.InalogyAuthenticatorToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialValidator;
import org.apereo.cas.otp.web.flow.OneTimeTokenAccountConfirmSelectionRegistrationAction;
import org.apereo.cas.otp.web.flow.OneTimeTokenAccountSaveRegistrationAction;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.security.auth.login.FailedLoginException;

@RequiredArgsConstructor
@Slf4j
public class InalogyAuthenticatorValidateTokenAction extends AbstractMultifactorAuthenticationAction {
    protected final CasConfigurationProperties casProperties;
    protected final OneTimeTokenCredentialRepository repository;
    protected final MfaRequestMap mfaRequestMap;
    protected final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> validator;

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) throws Throwable {
        val pushId = requestContext.getFlowScope().get("pushAuthPushId", String.class);
        val accountId = requestContext.getRequestParameters().getRequired(OneTimeTokenAccountConfirmSelectionRegistrationAction.REQUEST_PARAMETER_ACCOUNT_ID, Long.class);
        val request = mfaRequestMap.getRequestByPushId(pushId);

        val authentication = WebUtils.getAuthentication(requestContext);
        val tokenCredential = new InalogyAuthenticatorTokenCredential(request.getOtp(), accountId, request.getUserResponse());
        val validatedToken = validator.validate(authentication, tokenCredential);
        if (validatedToken != null) {
            val principal = authentication.getPrincipal().getId();
            LOGGER.debug("Validated OTP token [{}] successfully for [{}]", validatedToken, principal);
            val validate = requestContext.getRequestParameters().getBoolean(OneTimeTokenAccountSaveRegistrationAction.REQUEST_PARAMETER_VALIDATE);
            if (validate == null || !validate) {
                validator.store(validatedToken);
            }
            return success();
        }
        LOGGER.warn("Authorization of OTP token [{}] has failed", request.getOtp());
        throw new FailedLoginException("Failed to authenticate code " + request.getOtp());
    }
}
