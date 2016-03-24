package org.wso2.carbon.identity.account.lock.constants;

public class AccountLockConstants {

    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
    public static final String FAILED_LOGIN_ATTEMPTS_CLAIM =
            "\thttp://wso2.org/claims/identity/failedLoginAttempts";

    public static final String ACCOUNT_LOCKED_PROPERTY = "accountLock.enable";
    public static final String ACCOUNT_UNLOCK_TIME_PROPERTY = "accountLock.Time";
    public static final String FAILED_LOGIN_ATTEMPTS_PROPERTY = "accountLock.On.Failure.Max.Attempts";

}
