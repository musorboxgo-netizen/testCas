package cz.ami.cas.inauth.web.flow;

public interface InalogyWebflowConstants {

    String TRANSITION_ID_TIMEOUT = "timeout";

    String TRANSITION_ID_REJECTED = "rejected";

    String TRANSITION_ID_WAIT = "wait";

    String TRANSITION_ID_DISPLAY = "display";

    String TRANSITION_ID_DEVICE_NOT_REGISTERED = "deviceNotRegistered";

    String ACTION_ID_INALOGY_PREPARE_LOGIN = "inalogyPrepareLoginAction";

    String ACTION_ID_INALOGY_CHECK_ACCOUNT_REGISTRATION = "inalogyAccountCheckRegistrationAction";

    String ACTION_ID_INALOGY_SAVE_ACCOUNT_REGISTRATION = "inalogySaveAccountRegistrationAction";

    String ACTION_ID_INALOGY_VALIDATE_SELECTED_REGISTRATION = "inalogyValidateSelectedRegistrationAction";

    String ACTION_ID_INALOGY_ACCOUNT_CREATE_REGISTRATION = "inalogyAccountCreateRegistrationAction";

    String ACTION_ID_INALOGY_CONFIRM_SELECTION = "inalogyConfirmSelectionAction";

    String ACTION_ID_INALOGY_ACCOUNT_DELETE_DEVICE = "inalogyAccountDeleteDeviceAction";

    String ACTION_ID_INALOGY_VALIDATE_TOKEN = "inalogyValidateTokenAction";

    String ACTION_ID_INALOGY_CHECK_RESPONSE = "inalogyPushCheckResponseAction";

    String ACTION_ID_INALOGY_PUSH_INIT = "inalogyPushInitAction";

    String ACTION_ID_INALOGY_DECIDE_DOWNLOAD = "inalogyDisplayDownloadAction";

    String ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_PREPARE = "inalogyAccountProfilePrepareAction";

    String ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_REGISTRATION = "inalogyAccountProfileRegistrationAction";

    String ACTION_ID_ACCOUNT_PROFILE_INALOGY_MFA_DEVICE_PROVIDER = "inalogyAccountDeviceProviderAction";

    String STATE_ID_INALOGY_SAVE_REGISTRATION = "inalogyAccountSaveRegistration";

    String STATE_ID_INALOGY_DECIDE_DOWNLOAD = "inalogyDecideDownload";

    String STATE_ID_INALOGY_DISPLAY_DOWNLOAD = "inalogyDisplayDownloadQrCode";

    String STATE_ID_INALOGY_INIT_MFA = "inalogyInitMfaWebflow";

    String STATE_ID_MY_ACCOUNT_PROFILE_INALOGY_REGISTRATION_FINALIZED = "inalogyAccountProfileRegistrationFinalized";

    String STATE_ID_CHECK_PUSH_RESPONSE = "inalogyCheckPushResponse";
}
