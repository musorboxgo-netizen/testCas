package cz.ami.cas.inauth.web.flow.action;

import cz.ami.cas.inauth.credential.InalogyAuthenticatorTokenCredential;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.web.flow.InalogyWebflowConstants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import static org.apereo.cas.web.flow.CasWebflowConstants.VAR_ID_CREDENTIAL;

@Slf4j
@RequiredArgsConstructor
public class InalogyPushCheckResponseAction extends AbstractMultifactorAuthenticationAction {

    private final IInalogyAuthenticator inalogyAuthenticator;

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) {
        val pushId = requestContext.getFlowScope().getString("pushAuthPushId");
        if (pushId == null) {
            LOGGER.error("No pushAutnPushId found in flow scope");
            return error();
        }

        val status = inalogyAuthenticator.checkPushAuthenticationStatus(pushId);

        switch (status) {
            case APPROVED:
                LOGGER.debug("Push authentication approved for pushId: [{}]", pushId);
                val mfaRequest = inalogyAuthenticator.getPendingPushAuthentication(pushId);
                var cred = requestContext.getFlowScope().get(VAR_ID_CREDENTIAL, InalogyAuthenticatorTokenCredential.class);
                cred.setUserResponse(mfaRequest.getUserResponse());
                cred.setToken(mfaRequest.getOtp());
                cred.setAccountId(mfaRequest.getAccountId());
                requestContext.getFlowScope().put(VAR_ID_CREDENTIAL, cred);
                return new EventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_SUBMIT);

            case REJECTED:
                LOGGER.debug("Push authentication rejected for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, InalogyWebflowConstants.TRANSITION_ID_REJECTED);

            case NOT_FOUND:
                LOGGER.debug("Push authentication not found for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, InalogyWebflowConstants.TRANSITION_ID_REJECTED);

            case PENDING:
            default:
                val waitStartTime = requestContext.getFlowScope().getLong("pushAuthWaitStartTime",
                        System.currentTimeMillis());
                val currentTime = System.currentTimeMillis();
                val waitTime = currentTime - waitStartTime;

                if (waitTime > 60000) {
                    LOGGER.debug("Push authentication UI timeout for pushId: [{}]", pushId);
                    return new EventFactorySupport().event(this, InalogyWebflowConstants.TRANSITION_ID_TIMEOUT);
                }

                LOGGER.debug("Push authentication still pending for pushId: [{}]", pushId);
                return new EventFactorySupport().event(this, InalogyWebflowConstants.TRANSITION_ID_WAIT);
        }
    }
}
