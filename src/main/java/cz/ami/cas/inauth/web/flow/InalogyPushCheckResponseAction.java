package cz.ami.cas.inauth.web.flow;

import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Slf4j
@RequiredArgsConstructor
public class InalogyPushCheckResponseAction extends AbstractMultifactorAuthenticationAction {

    private final IInalogyAuthenticator inalogyAuthenticator;

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) {
        val pushId = requestContext.getFlowScope().getString("pushAutnPushId");
        if (pushId == null) {
            LOGGER.error("No pushAuthKeyId found in flow scope");
            return error();
        }

        val status = inalogyAuthenticator.checkPushAuthenticationStatus(pushId);

        switch (status) {
            case APPROVED:
                LOGGER.debug("Push authentication approved for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, "submit");

            case REJECTED:
                LOGGER.debug("Push authentication rejected for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, "rejected");

            case EXPIRED:
                LOGGER.debug("Push authentication expired for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, "timeout");

            case NOT_FOUND:
                LOGGER.debug("Push authentication not found for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, "timeout");

            case PENDING:
            default:
                val waitStartTime = requestContext.getFlowScope().getLong("pushAuthWaitStartTime",
                        System.currentTimeMillis());
                val currentTime = System.currentTimeMillis();
                val waitTime = currentTime - waitStartTime;

                if (waitTime > 60000) {
                    LOGGER.debug("Push authentication UI timeout for pushId: [{}]", pushId);
                    return new EventFactorySupport().event(this, "timeout");
                }

                LOGGER.debug("Push authentication still pending for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, "waiting");
        }
    }
}
