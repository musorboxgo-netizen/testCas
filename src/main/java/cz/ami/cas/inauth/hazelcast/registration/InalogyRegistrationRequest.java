package cz.ami.cas.inauth.hazelcast.registration;

import cz.ami.cas.inauth.authenticator.model.push.PushRegistrationStatus;
import cz.ami.cas.inauth.credential.InalogyAuthenticatorAccount;
import lombok.Builder;
import lombok.Data;
import org.apereo.cas.authentication.OneTimeTokenAccount;

import java.io.Serializable;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Data
@Builder
public class InalogyRegistrationRequest implements Serializable {
    private long   id;
    private String requestId;
    private String username;
    private String deviceName;
    private String deviceType;
    private String pushId;
    private String deviceKeyId;
    private String encodedSecret;
    private String name;
    private int    validationCode;
    private List<Number> scratchCodes;
    private String source;
    private ZonedDateTime registrationDate = ZonedDateTime.now(ZoneOffset.UTC);

    private long validUntil;
    private PushRegistrationStatus status;

    public static InalogyRegistrationRequest of(OneTimeTokenAccount acct,
                                                long timeoutMs) {
        return InalogyRegistrationRequest.builder()
                .id(acct.getId())
                .requestId(UUID.randomUUID().toString()) // удобно: совпадает с ключом в /submit
                .username(acct.getUsername())
                .name(acct.getName())
                .deviceName(null)
                .deviceType(null)
                .pushId(null)
                .deviceKeyId(null)
                .encodedSecret(acct.getSecretKey())
                .validationCode(acct.getValidationCode())
                .scratchCodes(new ArrayList<>(acct.getScratchCodes()))
                .validUntil(System.currentTimeMillis() + timeoutMs)
                .status(PushRegistrationStatus.PENDING)
                .build();
    }

    boolean isExpired() {
        return System.currentTimeMillis() > validUntil;
    }
}
