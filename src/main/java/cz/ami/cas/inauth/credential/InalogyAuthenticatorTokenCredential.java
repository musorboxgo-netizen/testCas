package cz.ami.cas.inauth.credential;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.apereo.cas.authentication.credential.OneTimeTokenCredential;

import java.io.Serial;

@NoArgsConstructor(force = true)
@Getter
@Setter
@ToString(callSuper = true)
public class InalogyAuthenticatorTokenCredential extends OneTimeTokenCredential {

    @Serial
    private static final long serialVersionUID = -7570600749902111127L;

    private Long accountId;

    public InalogyAuthenticatorTokenCredential(final String token, final Long accountId) {
        super(token);
        setAccountId(accountId);
    }
}
