package cz.ami.cas.inauth.web.flow.action;

import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import cz.ami.cas.inauth.web.flow.InalogyWebflowConstants;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.otp.util.QRUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.BaseCasWebflowAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

@Slf4j
@RequiredArgsConstructor
public class InalogyAuthenticatorDecideQrDisplay extends BaseCasWebflowAction {

    private final InalogyAuthenticatorMultifactorProperties multifactorProperties;

    @Override
    protected Event doExecuteInternal(RequestContext ctx) throws Exception {
        if (multifactorProperties.getDownload().isDisplayDownloadPage()){
            val keyUri = multifactorProperties.getCore().getCallbackUrl() + "/qr-redirect";

            val qrCodeBase64 = QRUtils.generateQRCode(keyUri, QRUtils.SIZE, QRUtils.SIZE);

            var flowScope = ctx.getFlowScope();
            flowScope.put("qrDataUri", qrCodeBase64);
            return new Event(this, InalogyWebflowConstants.TRANSITION_ID_DISPLAY);
        } else {
            return new Event(this, CasWebflowConstants.TRANSITION_ID_REGISTER);
        }
    }
}
