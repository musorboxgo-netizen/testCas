package cz.ami.cas.inauth.credential.repository;

import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import cz.ami.cas.inauth.service.IInalogyAuthenticator;
import lombok.Getter;
import lombok.val;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.util.crypto.CipherExecutor;

import java.util.ArrayList;
import java.util.UUID;

@Getter
public abstract class BaseInalogyAuthenticatorTokenCredentialRepository extends AbstractOneTimeTokenCredentialRepository {
    /**
     * Default bean name.
     */
    public static final String BEAN_NAME = "inalogyAuthenticatorAccountRegistry";

    /**
     * Inalogy authenticator token creator.
     */
    protected final IInalogyAuthenticator inalogyAuthenticator;

    protected BaseInalogyAuthenticatorTokenCredentialRepository(
            final CipherExecutor<String, String> tokenCredentialCipher,
            final CipherExecutor<Number, Number> scratchCodesCipher,
            final IInalogyAuthenticator inalogyAuthenticator) {
        super(tokenCredentialCipher, scratchCodesCipher);
        this.inalogyAuthenticator = inalogyAuthenticator;
    }

    @Override
    public OneTimeTokenAccount getByPushId(final String pushId) {
        val account = (load().stream()
                .filter(acc -> acc instanceof InalogyAuthenticatorAccount)
                .map(acc -> (InalogyAuthenticatorAccount) acc)
                .filter(acc -> pushId.equals(acc.getPushId()))
                .findFirst());
        return account.map(this::decode).orElse(null);
    }

    @Override
    public OneTimeTokenAccount getByDeviceKeyId(final String keyId) {
        val account = (load().stream()
                .filter(acc -> acc instanceof InalogyAuthenticatorAccount)
                .map(acc -> (InalogyAuthenticatorAccount) acc)
                .filter(acc -> keyId.equals(acc.getDeviceKeyId()))
                .findFirst());
        return account.map(this::decode).orElse(null);
    }

    @Override
    public OneTimeTokenAccount create(final String username) {
        val key = getInalogyAuthenticator().createCredentials();
        return InalogyAuthenticatorAccount.builder()
                .username(username)
                .secretKey(key.getKey())
                .validationCode(key.getVerificationCode())
                .scratchCodes(new ArrayList<>(key.getScratchCodes()))
                .name(UUID.randomUUID().toString())
                .build();
    }
}
