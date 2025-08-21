package cz.ami.cas.inauth.web.flow.action.account;

import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import lombok.val;
import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.web.flow.actions.ConsumerExecutionAction;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;
import org.apereo.cas.web.support.WebUtils;

/**
 * This is {@link InalogyMultifactorAuthenticationAccountProfilePrepareAction}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
public class InalogyMultifactorAuthenticationAccountProfilePrepareAction extends ConsumerExecutionAction {
    public InalogyMultifactorAuthenticationAccountProfilePrepareAction(
            final OneTimeTokenCredentialRepository repository,
            final MultifactorAuthenticationProvider inalogyAuthenticatorMultifactorAuthenticationProvider,
            final CoreInalogyMultifactorProperties coreMfaProperties) {
        super(requestContext -> {
            val principal = WebUtils.getAuthentication(requestContext).getPrincipal();
            val enabled = (coreMfaProperties.isMultipleDeviceRegistrationEnabled() || repository.count(principal.getId()) == 0)
                && MultifactorAuthenticationWebflowUtils.isMultifactorDeviceRegistrationEnabled(requestContext);
            requestContext.getFlowScope().put("inalogyAccountProfileRegistrationEnabled", enabled);
            MultifactorAuthenticationWebflowUtils.putMultifactorAuthenticationProvider(requestContext, inalogyAuthenticatorMultifactorAuthenticationProvider);
        });
    }
}

