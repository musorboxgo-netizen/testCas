package cz.ami.cas.inauth.credential;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import cz.ami.cas.inauth.token.InalogyAuthenticatorToken;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialValidator;
import org.apereo.cas.otp.repository.token.OneTimeTokenRepository;

import javax.security.auth.login.AccountExpiredException;
import javax.security.auth.login.AccountNotFoundException;
import java.util.Collection;
import java.util.Optional;

/**
 * This is {@link InalogyAuthenticatorOneTimeTokenCredentialValidator}.
 *
 * @author Inalogy
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
@Getter
public class InalogyAuthenticatorOneTimeTokenCredentialValidator implements
    OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> {
    private final IInalogyAuthenticator inalogyAuthenticatorInstance;

    private final OneTimeTokenRepository tokenRepository;

    private final OneTimeTokenCredentialRepository credentialRepository;

    private static boolean isCredentialAssignedToAccount(final InalogyAuthenticatorTokenCredential credential,
                                                         final OneTimeTokenAccount account) {
        return credential.getAccountId() == null || credential.getAccountId() == account.getId();
    }

    @Override
    public InalogyAuthenticatorToken validate(final Authentication authentication,
                                             final InalogyAuthenticatorTokenCredential tokenCredential) throws Throwable {

        if (!StringUtils.isNumeric(tokenCredential.getToken())) {
            throw new PreventedException("Invalid non-numeric OTP format specified.");
        }

        val uid = authentication.getPrincipal().getId();
        val otp = Integer.parseInt(tokenCredential.getToken());
        LOGGER.trace("Received OTP [{}] assigned to account [{}]", otp, tokenCredential.getAccountId());

        LOGGER.trace("Received principal id [{}]. Attempting to locate account in credential repository...", uid);
        val accounts = credentialRepository.get(uid);
        if (accounts == null || accounts.isEmpty()) {
            throw new AccountNotFoundException(uid + " cannot be found in the registry");
        }

        if (accounts.size() > 1 && tokenCredential.getAccountId() == null) {
            throw new PreventedException("Account identifier must be specified if multiple accounts are registered for " + uid);
        }
        LOGGER.trace("Attempting to locate OTP token [{}] in token repository for [{}]...", otp, uid);
        if (this.tokenRepository.exists(uid, otp)) {
            throw new AccountExpiredException(uid + " cannot reuse OTP " + otp + " as it may be expired/invalid");
        }

        LOGGER.debug("Attempting to authorize OTP token [{}]...", otp);
        val result = getAuthorizedAccountForToken(tokenCredential, accounts)
            .or(() -> getAuthorizedScratchCodeForToken(tokenCredential, authentication, accounts));
        return result
            .map(acct -> new InalogyAuthenticatorToken(otp, uid))
            .orElse(null);
    }

    @Override
    @CanIgnoreReturnValue
    public OneTimeTokenCredentialValidator<InalogyAuthenticatorTokenCredential, InalogyAuthenticatorToken> store(
        final InalogyAuthenticatorToken validatedToken) {
        this.tokenRepository.store(validatedToken);
        return this;
    }

    @Override
    public boolean isTokenAuthorizedFor(final int token, final OneTimeTokenAccount account) {
        LOGGER.debug("Authorizing token [{}] against account [{}]", token, account);
        val authorized = inalogyAuthenticatorInstance.validateOtp(account, token);
        if (!authorized && account.getScratchCodes().stream().map(Number::intValue).toList().contains(token)) {
            LOGGER.debug("Token [{}] is a valid scratch code for account [{}]", token, account);
            account.getScratchCodes().removeIf(code -> code.intValue() == token);
            credentialRepository.update(account);
            return true;
        }
        return authorized;
    }

    protected Optional<InalogyAuthenticatorAccount> getAuthorizedScratchCodeForToken(
        final InalogyAuthenticatorTokenCredential tokenCredential,
        final Authentication authentication,
        final Collection<? extends OneTimeTokenAccount> accounts) {
        val uid = authentication.getPrincipal().getId();
        val otp = Integer.parseInt(tokenCredential.getToken());
        LOGGER.debug("Checking scratch code [{}] for user [{}]", otp, uid);
        return accounts
            .stream()
            .filter(ac -> isCredentialAssignedToAccount(tokenCredential, ac))
            .peek(ac -> LOGGER.debug("Comparing existing scratch codes [{}] for account [{}] against [{}]",
                ac.getScratchCodes(), ac.getId(), otp))
            .filter(ac -> ac.getScratchCodes().stream().map(Number::intValue).toList().contains(otp))
            .map(InalogyAuthenticatorAccount.class::cast)
            .peek(acct -> {
                LOGGER.info("Using scratch code [{}] to authenticate user [{}]. Scratch code will be removed", otp, uid);
                acct.getScratchCodes().removeIf(token -> token.intValue() == otp);
                credentialRepository.update(acct);
            })
            .findFirst();
    }

    protected Optional<InalogyAuthenticatorAccount> getAuthorizedAccountForToken(
        final InalogyAuthenticatorTokenCredential tokenCredential,
        final Collection<? extends OneTimeTokenAccount> accounts) {
        val otp = Integer.parseInt(tokenCredential.getToken());
        return accounts
            .stream()
            .filter(ac -> isCredentialAssignedToAccount(tokenCredential, ac) && isTokenAuthorizedFor(otp, ac))
            .map(InalogyAuthenticatorAccount.class::cast)
            .findFirst();
    }
}