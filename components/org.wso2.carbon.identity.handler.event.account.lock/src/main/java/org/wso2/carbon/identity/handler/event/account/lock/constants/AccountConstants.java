/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations und
 */

package org.wso2.carbon.identity.handler.event.account.lock.constants;

/**
 * Constants class.
 */
public class AccountConstants {

    public static final String ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String ACCOUNT_UNLOCK_TIME_CLAIM = "http://wso2.org/claims/identity/unlockTime";
    public static final String ACCOUNT_DISABLED_CLAIM = "http://wso2.org/claims/identity/accountDisabled";
    public static final String FAILED_LOGIN_ATTEMPTS_CLAIM =
            "http://wso2.org/claims/identity/failedLoginAttempts";
    public static final String FAILED_LOGIN_LOCKOUT_COUNT_CLAIM =
            "http://wso2.org/claims/identity/failedLoginLockoutCount";
    public static final String FAILED_LOGIN_ATTEMPTS_BEFORE_SUCCESS_CLAIM =
            "http://wso2.org/claims/identity/failedLoginAttemptsBeforeSuccess";

    public static final String ACCOUNT_LOCK_MAX_FAILED_ATTEMPTS_PROPERTY =
            "account.lock.handler.lock.on.max.failed.attempts.enable";
    public static final String ACCOUNT_DISABLED_PROPERTY = "account.disable.handler.enable";
    public static final String ACCOUNT_DISABLED_NOTIFICATION_INTERNALLY_MANAGE = "account.disable.handler.notification.manageInternally";

    public static final String ACCOUNT_UNLOCK_TIME_PROPERTY = "account.lock.handler.Time";
    public static final String FAILED_LOGIN_ATTEMPTS_PROPERTY = "account.lock.handler.On.Failure.Max.Attempts";
    public static final String LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY = "account.lock.handler.login.fail.timeout.ratio";
    public static final String NOTIFICATION_INTERNALLY_MANAGE = "account.lock.handler.notification.manageInternally";
    public static final String NOTIFY_ON_LOCK_DURATION_INCREMENT =
            "account.lock.handler.notification.notifyOnLockIncrement";
    public static final String ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_LOCK_NOTIFICATION_ENABLE_PROPERTY =
            "Recovery.AdminPasswordReset.AccountLockNotification";
    public static final String ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_UNLOCK_NOTIFICATION_ENABLE_PROPERTY =
            "Recovery.AdminPasswordReset.AccountUnlockNotification";

    public static final String EMAIL_TEMPLATE_TYPE_ACC_LOCKED = "accountlock";
    public static final String EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED = "accountunlock";

    public static final String EMAIL_TEMPLATE_TYPE_ACC_DISABLED = "accountdisable";
    public static final String EMAIL_TEMPLATE_TYPE_ACC_ENABLED = "accountenable";

    public static final String ACCOUNT_LOCK_BYPASS_ROLE = "Internal/system";

    public static final String ACCOUNT_STATE_CLAIM_URI = "http://wso2.org/claims/identity/accountState";
    public static final String ACCOUNT_LOCKED_REASON_CLAIM_URI = "http://wso2.org/claims/identity/lockedReason";
    public static final String PENDING_SELF_REGISTRATION = "PENDING_SR";
    public static final String PENDING_EMAIL_VERIFICATION = "PENDING_EV";
    public static final String PENDING_LITE_REGISTRATION = "PENDING_LR";
    public static final String PENDING_ADMIN_FORCED_USER_PASSWORD_RESET = "PENDING_FUPR";
    public static final String PENDING_ASK_PASSWORD = "PENDING_AP";
    public static final String LOCKED = "LOCKED";
    public static final String UNLOCKED = "UNLOCKED";
    public static final String DISABLED = "DISABLED";

    public static final String ADMIN_INITIATED = "AdminInitiated";
    public static final String ACCOUNT_UNLOCK_TIME = "AccountUnlockTime";

    public static final String EMAIL_TEMPLATE_TYPE_ACC_LOCKED_ADMIN_TRIGGERED = "accountlockadmin";
    public static final String EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_ADMIN_TRIGGERED = "accountunlockadmin";

    public static final String EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT = "accountlockfailedattempt";
    public static final String EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_TIME_BASED = "accountunlocktimebased";

    public static final String LOCK_DURATION_EMAIL_TEMPLATE_PARAMETER = "lock-duration";
}

