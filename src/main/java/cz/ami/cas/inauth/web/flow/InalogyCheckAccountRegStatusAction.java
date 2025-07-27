package cz.ami.cas.inauth.web.flow;

import cz.ami.cas.inauth.authenticator.repository.TemporaryAccountStorage;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Slf4j
public class InalogyCheckAccountRegStatusAction extends AbstractAction {

    private final TemporaryAccountStorage temporaryAccountStorage;

    public InalogyCheckAccountRegStatusAction(TemporaryAccountStorage temporaryAccountStorage) {
        this.temporaryAccountStorage = temporaryAccountStorage;
    }

    @Override
    protected Event doExecute(RequestContext requestContext) {
        val flowScope = requestContext.getFlowScope();
        val account = flowScope.get("key", OneTimeTokenAccount.class);

        if (account == null) {
            return new Event(this, CasWebflowConstants.TRANSITION_ID_ERROR);
        }

        // Проверяем статус регистрации
        val status = temporaryAccountStorage.getRegistrationStatus(account.getId());

        LOGGER.debug("Checking registration status for account ID [{}]: status is [{}]",
                account.getId(), status);

        return switch (status) {
            case TemporaryAccountStorage.STATUS_REGISTERED ->
                // Если зарегистрирован - переходим к инициализации push
                    success();
            case TemporaryAccountStorage.STATUS_REJECTED ->
                // Если отклонён - возвращаем stop
                    new Event(this, "stop");
            default ->
                // Если всё ещё ждём - продолжаем ожидание
                    new Event(this, "waiting");
        };
    }
}
