package org.apereo.cas.gauth;

import java.lang.annotation.*;

/**
 * This is {@link GoogleAuthenticatorBypassEvaluator}.
 *
 * @author Misagh Moayyed
 * @since 7.2.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Documented
public @interface GoogleAuthenticatorBypassEvaluator {
}
