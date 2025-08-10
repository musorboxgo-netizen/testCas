package cz.ami.cas.inauth.web.flow;

import cz.ami.cas.inauth.authenticator.repository.TemporaryAccountStorage;
import cz.ami.cas.inauth.hazelcast.registration.RegistrationRequestMap;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Slf4j
public class InalogyCheckAccountRegStatusAction extends AbstractAction {

    private final RegistrationRequestMap registrationRequestMap;

    public InalogyCheckAccountRegStatusAction(RegistrationRequestMap registrationRequestMap) {
        this.registrationRequestMap = registrationRequestMap;
    }

    @Override
    protected Event doExecute(RequestContext requestContext) {
        val flowScope = requestContext.getFlowScope();
        val account = flowScope.get("key", OneTimeTokenAccount.class);

        if (account == null) {
            return new Event(this, CasWebflowConstants.TRANSITION_ID_ERROR);
        }

        val registrationRequestId = flowScope.getString("registrationRequestId");

        val status = registrationRequestMap.getRequest(registrationRequestId).getStatus();

        LOGGER.debug("Checking registration status for account ID [{}]: status is [{}]",
                account.getId(), status);

        return switch (status) {
            case REGISTERED ->
                    success();
            case PENDING->
                    new Event(this, "waiting");
            default ->
                    new Event(this, "stop");
        };
    }
}
