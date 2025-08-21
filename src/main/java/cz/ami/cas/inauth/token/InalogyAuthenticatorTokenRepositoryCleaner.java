package cz.ami.cas.inauth.token;

import org.apereo.cas.otp.repository.token.OneTimeTokenRepository;
import org.apereo.cas.otp.repository.token.OneTimeTokenRepositoryCleaner;
import org.springframework.scheduling.annotation.Scheduled;

public class InalogyAuthenticatorTokenRepositoryCleaner extends OneTimeTokenRepositoryCleaner {

    public InalogyAuthenticatorTokenRepositoryCleaner(final OneTimeTokenRepository tokenRepository) {
        super(tokenRepository);
    }

    @Scheduled(
            cron = "${cas.authn.mfa.inalogy.cleaner.schedule.cron-expression:}",
            zone = "${cas.authn.mfa.inalogy.cleaner.schedule.cron-time-zone:}",
            initialDelayString = "${cas.authn.mfa.inalogy.cleaner.schedule.start-delay:PT30S}",
            fixedDelayString = "${cas.authn.mfa.inalogy.cleaner.schedule.repeat-interval:PT35S}")
    @Override
    public void clean() {
        super.clean();
    }
}
