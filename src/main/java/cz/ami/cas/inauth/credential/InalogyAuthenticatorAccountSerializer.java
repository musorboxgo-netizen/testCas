package cz.ami.cas.inauth.credential;

import org.apereo.cas.util.serialization.BaseJacksonSerializer;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.Serial;

/**
 * This is {@link InalogyAuthenticatorAccountSerializer}.
 *
 * @author Inalogy
 * @since 1.0.0
 */
public class InalogyAuthenticatorAccountSerializer extends BaseJacksonSerializer<InalogyAuthenticatorAccount> {
    @Serial
    private static final long serialVersionUID = 1466569521275630254L;

    protected InalogyAuthenticatorAccountSerializer(final ConfigurableApplicationContext applicationContext) {
        super(applicationContext, InalogyAuthenticatorAccount.class);
    }
}