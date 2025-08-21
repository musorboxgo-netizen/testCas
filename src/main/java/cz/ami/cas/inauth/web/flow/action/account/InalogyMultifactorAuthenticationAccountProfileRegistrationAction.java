package cz.ami.cas.inauth.web.flow.action.account;

import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.web.flow.actions.ConsumerExecutionAction;
import org.apereo.cas.web.flow.util.MultifactorAuthenticationWebflowUtils;

/**
 * This is {@link InalogyMultifactorAuthenticationAccountProfileRegistrationAction}.
 *
 * @author Misagh Moayyed
 * @since 7.0.0
 */
public class InalogyMultifactorAuthenticationAccountProfileRegistrationAction extends ConsumerExecutionAction {
    public InalogyMultifactorAuthenticationAccountProfileRegistrationAction(final MultifactorAuthenticationProvider provider) {
        super(requestContext -> MultifactorAuthenticationWebflowUtils.putMultifactorAuthenticationProvider(requestContext, provider));
    }
}

