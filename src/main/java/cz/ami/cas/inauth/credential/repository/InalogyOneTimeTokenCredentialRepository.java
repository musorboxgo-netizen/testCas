package cz.ami.cas.inauth.credential.repository;

import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;

public interface InalogyOneTimeTokenCredentialRepository extends OneTimeTokenCredentialRepository {

    OneTimeTokenAccount getByPushId(final String pushId);

    OneTimeTokenAccount getByDeviceKeyId(final String keyId);

}
