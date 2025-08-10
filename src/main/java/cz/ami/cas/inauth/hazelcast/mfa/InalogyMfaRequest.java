package cz.ami.cas.inauth.hazelcast.mfa;

import cz.ami.cas.inauth.authenticator.model.push.PushAuthenticationStatus;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;

@Data
@Builder
public class InalogyMfaRequest implements Serializable {
    private String requestId;
    private String userId;
    private String pushId;
    private Long accountId;
    private String otp;
    private String challengeType;
    private String challengeData;
    private String userResponse;
    private PushAuthenticationStatus status;
    private long validUntil;

    public boolean isExpired() {
        return System.currentTimeMillis() > validUntil;
    }
}
