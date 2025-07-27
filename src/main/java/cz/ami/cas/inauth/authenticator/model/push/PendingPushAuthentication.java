package cz.ami.cas.inauth.authenticator.model.push;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PendingPushAuthentication {
    private final String keyId;
    private final String username;
    private final String challengeType;
    private final String dataForChallenge;
    private final long createdAt;
    private final long validUntil;

    private boolean responded = false;
    private boolean approved = false;
    private long respondedAt = 0;

    public PendingPushAuthentication(String keyId, String username,
                                     String challengeType, String dataForChallenge,
                                     long validitySeconds) {
        this.keyId = keyId;
        this.username = username;
        this.challengeType = challengeType;
        this.dataForChallenge = dataForChallenge;
        this.createdAt = System.currentTimeMillis();
        this.validUntil = this.createdAt + (validitySeconds * 1000);
    }

    public boolean isExpired() {
        return System.currentTimeMillis() > validUntil;
    }

    public void setResponse(boolean approved) {
        this.responded = true;
        this.approved = approved;
        this.respondedAt = System.currentTimeMillis();
    }
}
