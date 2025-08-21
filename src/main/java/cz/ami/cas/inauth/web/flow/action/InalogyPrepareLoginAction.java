package cz.ami.cas.inauth.web.flow.action;

import lombok.RequiredArgsConstructor;
import lombok.val;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * This is {@link InalogyPrepareLoginAction}.
 * Prepares the login form for Inalogy Authenticator.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@RequiredArgsConstructor
public class InalogyPrepareLoginAction extends AbstractMultifactorAuthenticationAction {
    protected final CasConfigurationProperties casProperties;
    protected final OneTimeTokenCredentialRepository repository;

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) {
        val principal = resolvePrincipal(WebUtils.getAuthentication(requestContext).getPrincipal(), requestContext);
        
        // For simplified flow, we always want to show the registration page
        // So we don't need to check if multiple device registration is enabled
        
        // Still put the accounts in the context in case we need them
        MultifactorAuthenticationWebflowUtils.putOneTimeTokenAccounts(requestContext, repository.get(principal.getId()));
        return null;
    }
}