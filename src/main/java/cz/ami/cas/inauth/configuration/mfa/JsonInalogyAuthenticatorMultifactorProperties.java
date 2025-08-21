package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.model.SpringResourceProperties;

import java.io.Serial;

@Getter
@Setter
@Accessors(chain = true)
public class JsonInalogyAuthenticatorMultifactorProperties extends SpringResourceProperties {
    @Serial
    private static final long serialVersionUID = -2689792609544442618L;
}
