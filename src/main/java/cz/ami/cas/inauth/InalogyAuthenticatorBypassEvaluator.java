package cz.ami.cas.inauth;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Documented
public @interface InalogyAuthenticatorBypassEvaluator {
}
