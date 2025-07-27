package cz.ami.cas.inauth.web.flow;

import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.web.flow.OneTimeTokenAccountCheckRegistrationAction;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

public class InalogyAuthenticatorAccountCheckRegistrationAction extends OneTimeTokenAccountCheckRegistrationAction {
    public InalogyAuthenticatorAccountCheckRegistrationAction(final OneTimeTokenCredentialRepository repository,
                                                             final CasConfigurationProperties casProperties) {
        super(repository, casProperties);
    }

    @Override
    protected Event routeToRegistration(final RequestContext requestContext, final Principal principal) {
        if (!casProperties.getAuthn().getMfa().getInalogy().getCore().isDeviceRegistrationEnabled()) {
            return new EventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_STOP);
        }
        return super.routeToRegistration(requestContext, principal);
    }
}