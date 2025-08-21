package cz.ami.cas.inauth.token;

import lombok.NoArgsConstructor;
import org.apereo.cas.authentication.OneTimeToken;

import java.io.Serial;

@NoArgsConstructor
public class InalogyAuthenticatorToken extends OneTimeToken {
    @Serial
    private static final long serialVersionUID = 8494781664790219070L;

    public InalogyAuthenticatorToken(final Integer token, final String userId) {
        super(token, userId);
    }
}
