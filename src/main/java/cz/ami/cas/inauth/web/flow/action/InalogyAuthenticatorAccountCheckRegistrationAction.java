package cz.ami.cas.inauth.web.flow.action;

import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.web.flow.OneTimeTokenAccountCheckRegistrationAction;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

public class InalogyAuthenticatorAccountCheckRegistrationAction extends OneTimeTokenAccountCheckRegistrationAction {

    private final CoreInalogyMultifactorProperties mfaProperties;

    public InalogyAuthenticatorAccountCheckRegistrationAction(final OneTimeTokenCredentialRepository repository,
                                                              final CasConfigurationProperties casProperties,
                                                              final CoreInalogyMultifactorProperties mfaProperties) {
        super(repository, casProperties);
        this.mfaProperties = mfaProperties;
    }

    @Override
    protected Event routeToRegistration(final RequestContext requestContext, final Principal principal) {
        if (!mfaProperties.isDeviceRegistrationEnabled()) {
            return new EventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_STOP);
        }
        return super.routeToRegistration(requestContext, principal);
    }
}