package cz.ami.cas.inauth.web.flow.action;

import cz.ami.cas.inauth.configuration.mfa.CoreInalogyMultifactorProperties;
import cz.ami.cas.inauth.hazelcast.registration.InalogyRegistrationRequest;
import cz.ami.cas.inauth.hazelcast.registration.RegistrationRequestMap;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.util.QRUtils;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.flow.actions.AbstractMultifactorAuthenticationAction;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.webflow.action.EventFactorySupport;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * This is {@link InalogyAccountCreateRegistrationAction}.
 * Creates a new account and generates a QR code for Inalogy Authenticator.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class InalogyAccountCreateRegistrationAction extends AbstractMultifactorAuthenticationAction {
    /**
     * Flow scope attribute name indicating the account.
     */
    public static final String FLOW_SCOPE_ATTR_ACCOUNT = "key";

    /**
     * Flow scope attribute name indicating the account QR code.
     */
    public static final String FLOW_SCOPE_ATTR_QR_IMAGE_BASE64 = "QRcode";

    private final OneTimeTokenCredentialRepository repository;

    private final RegistrationRequestMap registrationRequestMap;

    private final CoreInalogyMultifactorProperties properties;

    @Override
    protected Event doExecuteInternal(final RequestContext requestContext) throws Exception {
        val principal = resolvePrincipal(WebUtils.getAuthentication(requestContext).getPrincipal(), requestContext);
        val uid = principal.getId();

        val keyAccount = repository.create(uid);
        val registrationRequest = InalogyRegistrationRequest.of(keyAccount, properties.getTimeoutMs());
        registrationRequestMap.putRequest(registrationRequest);


        val callbackUrlEncoded = URLEncoder.encode(properties.getCallbackUrl(), StandardCharsets.UTF_8);

        val keyUri = String.format("otpauth://totp/%s:%s?secret=%s&digits=6&mode=push&algorithm=SHA256&issuer=%s&callback=%s&period=30",
                properties.getLabel(),
                uid,
                keyAccount.getSecretKey(),
                properties.getIssuer(),
                callbackUrlEncoded
        );

        val qrCodeBase64 = QRUtils.generateQRCode(keyUri, QRUtils.SIZE, QRUtils.SIZE);

        val flowScope = requestContext.getFlowScope();
        flowScope.put(FLOW_SCOPE_ATTR_ACCOUNT, keyAccount);
        flowScope.put("regRequestId", registrationRequest.getRequestId());
        flowScope.put(FLOW_SCOPE_ATTR_QR_IMAGE_BASE64, qrCodeBase64);
        flowScope.put("redirectSeconds", properties.getRedirectSeconds());

        LOGGER.debug("Inalogy registration key URI: [{}]", keyUri);

        return new EventFactorySupport().event(this, CasWebflowConstants.TRANSITION_ID_REGISTER);
    }
}