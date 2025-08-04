package cz.ami.cas.inauth.credential;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.apereo.cas.authentication.OneTimeTokenAccount;

import java.io.Serial;

@NoArgsConstructor
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@SuperBuilder
@Getter
@Setter
public class InalogyAuthenticatorAccount extends OneTimeTokenAccount {
    @Serial
    private static final long serialVersionUID = 2441771266526250011L;

    private String deviceType;    // IOS или ANDROID
    private String pushId;        // Push notification token
    private String deviceKeyId;

    /**
     * From one time token account into inalogy account.
     *
     * @param acct the acct
     * @return the inalogy authenticator account
     */
    public static InalogyAuthenticatorAccount from(final OneTimeTokenAccount acct) {
        InalogyAuthenticatorAccount account = builder()
                .id(acct.getId())
                .name(acct.getName())
                .username(acct.getUsername())
                .secretKey(acct.getSecretKey())
                .validationCode(acct.getValidationCode())
                .scratchCodes(acct.getScratchCodes())
                .registrationDate(acct.getRegistrationDate())
                .source(acct.getSource())
                .build();

        if (acct instanceof InalogyAuthenticatorAccount) {
            InalogyAuthenticatorAccount inalogyAcct = (InalogyAuthenticatorAccount) acct;
            account.setDeviceType(inalogyAcct.getDeviceType());
            account.setPushId(inalogyAcct.getPushId());
            account.setDeviceKeyId(inalogyAcct.getDeviceKeyId());
        }

        return account;
    }

    @Override
    public String getSource() {
        return "Inalogy Authenticator";
    }
}
