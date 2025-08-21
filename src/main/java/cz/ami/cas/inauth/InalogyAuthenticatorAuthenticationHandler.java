package cz.ami.cas.inauth;

import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import cz.ami.cas.inauth.token.InalogyAuthenticatorToken;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.MultifactorAuthenticationHandler;
import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.authentication.handler.support.AbstractPreAndPostProcessingAuthenticationHandler;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.monitor.Monitorable;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialValidator;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.beans.factory.ObjectProvider;

import javax.security.auth.login.FailedLoginException;
import java.util.Objects;

@Slf4j
@Getter
@Monitorable
public class InalogyAuthenticatorAuthenticationHandler extends AbstractPreAndPostProcessingAuthenticationHandler implements MultifactorAuthenticationHandler {

    private final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> validator;

    private final ObjectProvider<MultifactorAuthenticationProvider> multifactorAuthenticationProvider;

    public InalogyAuthenticatorAuthenticationHandler(
            final String name,
            final ServicesManager servicesManager,
            final PrincipalFactory principalFactory,
            final OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> validator,
            final Integer order, final ObjectProvider<MultifactorAuthenticationProvider> multifactorAuthenticationProvider) {
        super(name, servicesManager, principalFactory, order);
        this.validator = validator;
        this.multifactorAuthenticationProvider = multifactorAuthenticationProvider;
    }

    @Override
    public boolean supports(final Class<? extends Credential> clazz) {
        return InalogyAuthenticatorTokenCredential.class.isAssignableFrom(clazz);
    }

    @Override
    public boolean supports(final Credential credential) {
        return InalogyAuthenticatorTokenCredential.class.isAssignableFrom(credential.getClass());
    }

    @Override
    protected AuthenticationHandlerExecutionResult doAuthentication(final Credential credential, final Service service) throws Throwable {
        val tokenCredential = (InalogyAuthenticatorTokenCredential) credential;
        val authentication = Objects.requireNonNull(WebUtils.getInProgressAuthentication());
        Objects.requireNonNull(authentication, "No authentication is available to determine the principal");
        val validatedToken = validator.validate(authentication, tokenCredential);
        if (validatedToken != null) {
            val principal = authentication.getPrincipal().getId();
            LOGGER.debug("Validated OTP token [{}] successfully for [{}]", validatedToken, principal);
            validator.store(validatedToken);
            LOGGER.debug("Creating authentication result and building principal for [{}]", principal);
            return createHandlerResult(tokenCredential, this.principalFactory.createPrincipal(principal));
        }
        LOGGER.warn("Authorization of OTP token [{}] has failed", credential);
        throw new FailedLoginException("Failed to authenticate code " + credential);
    }
}
