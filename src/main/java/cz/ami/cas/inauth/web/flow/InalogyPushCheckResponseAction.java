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
        val keyId = requestContext.getFlowScope().getString("pushAuthKeyId");
        if (keyId == null) {
            LOGGER.error("No pushAuthKeyId found in flow scope");
            return error();
        }

        // Проверяем статус аутентификации
        val status = inalogyAuthenticator.checkPushAuthenticationStatus(keyId);

        switch (status) {
            case APPROVED:
                LOGGER.debug("Push authentication approved for keyId: [{}]", keyId);
                return new EventFactorySupport().event(this, "submit");

            case REJECTED:
                LOGGER.debug("Push authentication rejected for keyId: [{}]", keyId);
                return new EventFactorySupport().event(this, "rejected");

            case EXPIRED:
                LOGGER.debug("Push authentication expired for keyId: [{}]", keyId);
                return new EventFactorySupport().event(this, "timeout");

            case NOT_FOUND:
                LOGGER.debug("Push authentication not found for keyId: [{}]", keyId);
                return new EventFactorySupport().event(this, "timeout");

            case PENDING:
            default:
                // Проверяем, не истекло ли время ожидания в UI
                val waitStartTime = requestContext.getFlowScope().getLong("pushAuthWaitStartTime",
                        System.currentTimeMillis());
                val currentTime = System.currentTimeMillis();
                val waitTime = currentTime - waitStartTime;

                if (waitTime > 60000) { // 1 минута тайм-аут UI
                    LOGGER.debug("Push authentication UI timeout for keyId: [{}]", keyId);
                    return new EventFactorySupport().event(this, "timeout");
                }

                LOGGER.debug("Push authentication still pending for keyId: [{}]", keyId);
                return new EventFactorySupport().event(this, "waiting");
        }
    }
}
