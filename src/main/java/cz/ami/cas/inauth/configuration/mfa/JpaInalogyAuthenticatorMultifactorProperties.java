package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.apereo.cas.configuration.model.support.jpa.AbstractJpaProperties;

import java.io.Serial;

@Getter
@Setter
@Accessors(chain = true)
public class JpaInalogyAuthenticatorMultifactorProperties extends AbstractJpaProperties {
    @Serial
    private static final long serialVersionUID = -2689794478546888622L;

    private boolean enabled = false;
}
