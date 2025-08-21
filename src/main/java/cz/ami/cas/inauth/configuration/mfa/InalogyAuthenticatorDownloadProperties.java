package cz.ami.cas.inauth.configuration.mfa;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InalogyAuthenticatorDownloadProperties {
    private boolean displayDownloadPage = true;
    private String googlePlayAppUrl = "https://play.google.com/store/apps/details?id=com.inalogy.pushauthenticator";
    private String appStoreAppUrl = "https://apps.apple.com/us/app/inalogy-authenticator";
}
