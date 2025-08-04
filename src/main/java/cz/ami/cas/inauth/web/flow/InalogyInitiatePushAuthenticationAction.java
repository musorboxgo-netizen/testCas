package cz.ami.cas.inauth.web.flow;

import cz.ami.cas.inauth.authenticator.model.push.PendingPushAuthentication;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
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

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) {
        val authentication = WebUtils.getAuthentication(requestContext);
        if (authentication == null) {
            LOGGER.error("No authentication found in the context");
            return error();
        }

        val principal = authentication.getPrincipal();
        val username = principal.getId();

        // Инициируем push-аутентификацию
        String keyId = inalogyAuthenticatorService.initiatePushAuthentication(username);

        if (keyId == null) {
            LOGGER.warn("Failed to initiate push authentication for user: [{}]", username);
            return new EventFactorySupport().event(this, "deviceNotRegistered");
        }

        PendingPushAuthentication authn = inalogyAuthenticatorService.getPendingPushAuthentication(keyId);

        // Сохраняем keyId в flow scope для последующей проверки
        requestContext.getFlowScope().put("pushAuthKeyId", keyId);
        requestContext.getFlowScope().put("pushAuthWaitStartTime", System.currentTimeMillis());
        requestContext.getFlowScope().put("challengeType", authn.getChallengeType());
        requestContext.getFlowScope().put("challengeData", authn.getDataForChallenge());

        LOGGER.debug("Push authentication initiated for user: [{}], keyId: [{}]", username, keyId);
        return success();
    }
}
