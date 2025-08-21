package cz.ami.cas.inauth;

import cz.ami.cas.inauth.configuration.mfa.InalogyAuthenticatorMultifactorProperties;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.AbstractMultifactorAuthenticationProvider;

import java.io.Serial;

@NoArgsConstructor
public class InalogyAuthenticatorMultifactorAuthenticationProvider extends AbstractMultifactorAuthenticationProvider {

    @Serial
    private static final long serialVersionUID = 4789727148634156909L;

    @Override
    public String getId() {
        return StringUtils.defaultIfBlank(super.getId(), InalogyAuthenticatorMultifactorProperties.DEFAULT_IDENTIFIER);
    }

    @Override
    public String getFriendlyName() {
        return "Inalogy Authenticator";
    }
}
