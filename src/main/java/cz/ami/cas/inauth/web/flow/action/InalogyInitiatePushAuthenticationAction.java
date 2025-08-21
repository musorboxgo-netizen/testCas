package cz.ami.cas.inauth.web.flow.action;

import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import cz.ami.cas.inauth.hazelcast.mfa.InalogyMfaRequest;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.web.flow.InalogyWebflowConstants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Slf4j
@RequiredArgsConstructor
public class InalogyInitiatePushAuthenticationAction extends AbstractMultifactorAuthenticationAction {

    private final IInalogyAuthenticator inalogyAuthenticatorService;

    private final CoreInalogyMultifactorProperties properties;

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) {
        val authentication = WebUtils.getAuthentication(requestContext);
        if (authentication == null) {
            LOGGER.error("No authentication found in the context");
            return error();
        }

        val principal = authentication.getPrincipal();
        val username = principal.getId();

        String pushId = inalogyAuthenticatorService.initiatePushAuthentication(username);

        if (pushId == null) {
            LOGGER.warn("Failed to initiate push authentication for user: [{}]", username);
            return new EventFactorySupport().event(this, InalogyWebflowConstants.TRANSITION_ID_DEVICE_NOT_REGISTERED);
        }

        InalogyMfaRequest authn = inalogyAuthenticatorService.getPendingPushAuthentication(pushId);

        requestContext.getFlowScope().put("pushAuthPushId", pushId);
        requestContext.getFlowScope().put("pushAuthWaitStartTime", System.currentTimeMillis());
        requestContext.getFlowScope().put("challengeType", authn.getChallengeType());
        requestContext.getFlowScope().put("challengeData", authn.getChallengeData());
        requestContext.getFlowScope().put("redirectSeconds", properties.getRedirectSeconds());


        LOGGER.debug("Push authentication initiated for user: [{}], pushId: [{}]", username, pushId);
        return success();
    }
}
