/*
 * Copyright (c) 2016-2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.handler.event.account.lock;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityMgtConstants;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.identity.handler.event.account.lock.util.AccountUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.identity.governance.IdentityMgtConstants.LockedReason.MAX_ATTEMPTS_EXCEEDED;
import static org.wso2.carbon.identity.governance.IdentityMgtConstants.LockedReason.ADMIN_INITIATED;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_LOCKED_CLAIM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM;
import static org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.INVALID_CREDENTIAL;
import static org.wso2.carbon.user.core.UserCoreConstants.ErrorCode.USER_IS_LOCKED;

/**
 * Implementation of account lock handler.
 */
public class AccountLockHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    public static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");
    private static final Log log = LogFactory.getLog(AccountLockHandler.class);
    public static final String TOKEN_EXCHANGE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

    private static ThreadLocal<String> lockedState = new ThreadLocal<>();

    private enum lockedStates {LOCKED_MODIFIED, UNLOCKED_MODIFIED, LOCKED_UNMODIFIED, UNLOCKED_UNMODIFIED}

    public String getName() {
        return "account.lock.handler";
    }

    public String getFriendlyName() {
        return "Account Lock";
    }

    @Override
    public String getCategory() {
        return "Login Attempts Security";
    }

    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public void init(InitConfig initConfig) {
        super.init(initConfig);
        AccountServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityConnectorConfig.class.getName(), this, null);
    }

    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(AccountConstants.ACCOUNT_LOCK_MAX_FAILED_ATTEMPTS_PROPERTY,
                "Lock user accounts on maximum failed attempts");
        nameMapping.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Maximum failed login attempts");
        nameMapping.put(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Initial account lock duration");
        nameMapping.put(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY, "Account lock duration increment factor");
        nameMapping.put(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE, "Manage notification sending internally");
        nameMapping.put(AccountConstants.NOTIFY_ON_LOCK_DURATION_INCREMENT, "Notify user when lock time is increased");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(AccountConstants.ACCOUNT_LOCK_MAX_FAILED_ATTEMPTS_PROPERTY,
                "Lock user accounts on failed login attempts");
        descriptionMapping.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Number of failed login attempts " +
                "allowed until account lock.");
        descriptionMapping.put(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Initial account lock time period in " +
                "minutes. Account will be automatically unlocked after this time period.");
        descriptionMapping.put(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY, "Account lock duration will be " +
                "increased by this factor. Ex: Initial duration: 5m; Increment factor: 2; Next lock duration: 5 x 2 = 10m");
        descriptionMapping.put(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE, "Disable if the client application " +
                "handles notification sending");
        descriptionMapping.put(AccountConstants.NOTIFY_ON_LOCK_DURATION_INCREMENT, "Notify user when the account " +
                "lock duration is increased due to continuous failed login attempts.");
        return descriptionMapping;
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 100;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        // This property is added to disable the account lock handler completely to enhance the performance. This
        // can be done only where we are not using any account lock related features.
        if (Boolean.parseBoolean(IdentityUtil.getProperty(AccountConstants.DISABLE_ACCOUNT_LOCK_HANDLER))) {
            return;
        }

        Map<String, Object> eventProperties = event.getEventProperties();
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(USER_STORE_MANAGER);

        // Basic data from event.
        String userName = (String) eventProperties.get(USER_NAME);
        String userStoreDomainName = AccountUtil.getUserStoreDomainName(userStoreManager);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        // Check whether user exists.
        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, userStoreDomainName);
        boolean userExists;
        try {
            userExists = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error in accessing user store", e);
        }

        // If this user does not exist, no use of going forward.
        if (!userExists) {
            return;
        }

        // Force password related properties.
        String adminPasswordResetAccountLockNotificationProperty = IdentityUtil
                .getProperty(AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_LOCK_NOTIFICATION_ENABLE_PROPERTY);
        String adminPasswordResetAccountUnlockNotificationProperty = IdentityUtil
                .getProperty(AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_UNLOCK_NOTIFICATION_ENABLE_PROPERTY);
        boolean adminForcePasswordResetLockNotificationEnabled = Boolean
                .parseBoolean(adminPasswordResetAccountLockNotificationProperty);
        boolean adminForcePasswordResetUnlockNotificationEnabled = Boolean
                .parseBoolean(adminPasswordResetAccountUnlockNotificationProperty);

        // Read identity properties.
        Property[] identityProperties;
        try {
            identityProperties = AccountServiceDataHolder.getInstance().getIdentityGovernanceService()
                    .getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving Account Locking Handler properties.", e);
        }

        // We need to derive below values from identity properties.
        boolean accountLockOnFailedAttemptsEnabled = false;
        String accountLockTime = "0";
        int maximumFailedAttempts = 0;
        double unlockTimeRatio = 1;

        // Go through every property and get the values we need. These properties are from identity-event.properties
        // file.
        for (Property identityProperty : identityProperties) {
            switch (identityProperty.getName()) {
                case AccountConstants.ACCOUNT_LOCK_MAX_FAILED_ATTEMPTS_PROPERTY:
                    accountLockOnFailedAttemptsEnabled = Boolean.parseBoolean(identityProperty.getValue());
                    break;
                case AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY: {
                    String value = identityProperty.getValue();
                    if (NumberUtils.isNumber(value)) {
                        maximumFailedAttempts = Integer.parseInt(identityProperty.getValue());
                    }
                    break;
                }
                case AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY:
                    accountLockTime = identityProperty.getValue();
                    break;
                case AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY: {
                    String value = identityProperty.getValue();
                    if (NumberUtils.isNumber(value)) {
                        if (Integer.parseInt(value) > 0) {
                            unlockTimeRatio = Integer.parseInt(value);
                        }
                    }
                    break;
                }
            }
        }

        // Based on the event name, we need to handle each case separately.
        switch (event.getEventName()) {
            case IdentityEventConstants.Event.PRE_AUTHENTICATION:
                handlePreAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
                break;
            case IdentityEventConstants.Event.POST_AUTHENTICATION:
                handlePostAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                        accountLockOnFailedAttemptsEnabled);
                break;
            case IdentityEventConstants.Event.PRE_SET_USER_CLAIMS:
                handlePreSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
                break;
            case IdentityEventConstants.Event.POST_SET_USER_CLAIMS:
                PrivilegedCarbonContext.startTenantFlow();
                try {
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
                    handlePostSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                            identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                            adminForcePasswordResetLockNotificationEnabled,
                            adminForcePasswordResetUnlockNotificationEnabled);
                } finally {
                    PrivilegedCarbonContext.endTenantFlow();
                }
                break;
            case IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION:
                // This will be invoked when an authenticator fires event POST_NON_BASIC_AUTHENTICATION.
                // This is similar to the POST_AUTHENTICATION.
                handleNonBasicAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                        accountLockOnFailedAttemptsEnabled);
                break;
        }
    }

    protected boolean handlePreAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                              String userStoreDomainName, String tenantDomain,
                                              Property[] identityProperties, int maximumFailedAttempts,
                                              String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        // If the authorization policy to check whether the user exists is enabled and if user does not exist in the
        // given domain, we have to set an error.
        if (isAuthPolicyAccountExistCheck() && !isUserExistsInDomain(userStoreManager, userName)) {
            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants
                    .ErrorCode.USER_DOES_NOT_EXIST);
            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
        }

        if (AccountUtil.isPreAuthLockedAccountCheckEnabled()) {
            Map<String, String> claimValues;
            try {
                claimValues = userStoreManager.getUserClaimValues(userName,
                        new String[]{AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM,
                                AccountConstants.ACCOUNT_LOCKED_CLAIM,
                                AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI},
                        UserCoreConstants.DEFAULT_PROFILE);
            } catch (UserStoreException e) {
                throw new AccountLockException(String.format("Error occurred while retrieving %s, %s " +
                                "and %s claim values for user store domain: %s",
                        AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, AccountConstants.ACCOUNT_LOCKED_CLAIM,
                        AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, userStoreDomainName), e);
            }
            handleLockedAccount(userName, userStoreManager, userStoreDomainName, tenantDomain, claimValues);
        }

        return true;
    }

    protected boolean handleNonBasicAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                                   String userStoreDomainName, String tenantDomain,
                                                   Property[] identityProperties, int maximumFailedAttempts,
                                                   String accountLockTime, double unlockTimeRatio,
                                                   boolean accountLockOnFailedAttemptsEnabled)
            throws AccountLockException {

        /*
         * This is similar to the POST_AUTHENTICATION. If the authentication attempt at the authenticator is successful,
         * we need to reset any failed login attempts. If the authentication failed, we need to increment failed login
         * attempts and lock the user if the account lock criteria is satisfied.
         */
        return handlePostAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                accountLockOnFailedAttemptsEnabled);
    }

    protected boolean handlePostAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                               String userStoreDomainName, String tenantDomain,
                                               Property[] identityProperties, int maximumFailedAttempts,
                                               String accountLockTime, double unlockTimeRatio,
                                               boolean accountLockOnFailedAttemptsEnabled) throws AccountLockException {

        Map<String, String> claimValues = null;

        // Resolve the claim which stores failed attempts depending on the authenticator.
        Map<String, Object> eventProperties = event.getEventProperties();
        String authenticator = String.valueOf(eventProperties.get(AUTHENTICATOR_NAME));
        String failedAttemptsClaim = resolveFailedLoginAttemptsCounterClaim(authenticator, eventProperties);

        try {
            claimValues = userStoreManager.getUserClaimValues(userName,
                    new String[]{AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM,
                            AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                            AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, AccountConstants.ACCOUNT_LOCKED_CLAIM,
                            AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, failedAttemptsClaim},
                    UserCoreConstants.DEFAULT_PROFILE);

        } catch (UserStoreException e) {
            throw new AccountLockException(String.format("Error occurred while retrieving %s , %s , %s , %s, %s " +
                            "and %s claim values for user domain.", AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM,
                    AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM,
                    AccountConstants.ACCOUNT_LOCKED_CLAIM, AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                    failedAttemptsClaim, userStoreDomainName), e);
        }

        long unlockTime = getUnlockTime(claimValues.get(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM));

        if (!AccountUtil.isPreAuthLockedAccountCheckEnabled() &&
                handleLockedAccount(userName, userStoreManager, userStoreDomainName, tenantDomain, claimValues)) {
            /*
             * handleLockedAccount will return true if the account locking is bypassed for this user
             * in which case we don't need to proceed.
             */
            return true;
        }

        // TODO: Move GrantType to IdentityCoreConstants.
        // Skip updating account lock claims for the token exchange grant type,
        // as this flow only involves validation and not actual login attempts.
        if (StringUtils.equals((String) IdentityUtil.threadLocalProperties.get().get("GrantType"),
                TOKEN_EXCHANGE_GRANT_TYPE)) {
            return true;
        }

        if (!accountLockOnFailedAttemptsEnabled) {
            if (log.isDebugEnabled()) {
                log.debug("Account lock on failed login attempts is disabled in tenant: " + tenantDomain);
            }
            return true;
        }

        int currentFailedAttempts = 0;
        int currentFailedLoginLockouts = 0;

        // Get the account locking related claims from the user store.
        String currentFailedAttemptCount = claimValues.get(failedAttemptsClaim);
        if (StringUtils.isNotBlank(currentFailedAttemptCount)) {
            currentFailedAttempts = Integer.parseInt(currentFailedAttemptCount);
        }
        String currentFailedLoginLockoutCount = claimValues.get(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM);
        if (StringUtils.isNotBlank(currentFailedLoginLockoutCount)) {
            currentFailedLoginLockouts = Integer.parseInt(currentFailedLoginLockoutCount);
        }

        Map<String, String> newClaims = new HashMap<>();
        if ((Boolean) event.getEventProperties().get(IdentityEventConstants.EventProperty.OPERATION_STATUS)) {

            // User is authenticated, Need to check the unlock-time to verify whether the user is previously locked.
            String accountLockClaim = claimValues.get(AccountConstants.ACCOUNT_LOCKED_CLAIM);

            // Return if user authentication is successful on the first try.
            if (!Boolean.parseBoolean(accountLockClaim) && currentFailedAttempts == 0 &&
                    currentFailedLoginLockouts == 0 && unlockTime == 0) {
                return true;
            }

            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_BEFORE_SUCCESS_CLAIM,
                    String.valueOf(currentFailedAttempts + (currentFailedLoginLockouts * maximumFailedAttempts)));
            if (isUserUnlockable(userName, userStoreManager, currentFailedAttempts, unlockTime, accountLockClaim)) {
                newClaims.put(failedAttemptsClaim, "0");
                newClaims.put(ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                newClaims.put(ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                boolean isAuthenticationFrameworkFlow = false;
                if (IdentityUtil.threadLocalProperties.get().get(
                        FrameworkConstants.AUTHENTICATION_FRAMEWORK_FLOW) != null) {
                    isAuthenticationFrameworkFlow = (boolean) IdentityUtil.threadLocalProperties.get().get(
                            FrameworkConstants.AUTHENTICATION_FRAMEWORK_FLOW);
                }
                if (!isAuthenticationFrameworkFlow) {
                    newClaims.put(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");
                }
                IdentityUtil.threadLocalProperties.get().put(AccountConstants.ADMIN_INITIATED, false);
            }
            setUserClaims(userName, tenantDomain, userStoreManager, newClaims);
        } else {
            // User authentication failed.
            // Skip account lock if account lock by pass is enabled for the userstore manager.
            if (AccountUtil.isAccountLockBypassForUserStore(userStoreManager)) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Account lock has been by passed for the %s userstore manager.",
                            userStoreManager.getRealmConfiguration().getRealmClassName()));
                }
                return true;
            }
            currentFailedAttempts += 1;
            newClaims.put(failedAttemptsClaim, Integer.toString(currentFailedAttempts));
            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_BEFORE_SUCCESS_CLAIM, "0");
            long accountLockDuration = 0;
            boolean isMaxAttemptsExceeded = false;

            if (AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)) {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(INVALID_CREDENTIAL,
                        currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                if (log.isDebugEnabled()) {
                    log.debug("Login attempt failed. Bypassing account locking for user: " + userName);
                }
                return true;
            } else if (currentFailedAttempts >= maximumFailedAttempts) {
                // Current failed attempts exceeded maximum allowed attempts. So user should be locked.
                isMaxAttemptsExceeded = true;
                newClaims.put(ACCOUNT_LOCKED_CLAIM, "true");
                newClaims.put(AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI, MAX_ATTEMPTS_EXCEEDED.toString());
                if (NumberUtils.isNumber(accountLockTime)) {
                    long unlockTimePropertyValue = Integer.parseInt(accountLockTime);
                    if (unlockTimePropertyValue != 0) {
                        if (log.isDebugEnabled()) {
                            String msg = String.format("Set account unlock time for user: %s in user store: %s " +
                                            "in tenant: %s. Adding account unlock time out: %s, account lock timeout " +
                                            "increment factor: %s raised to the power of failed login attempt cycles: %s",
                                    userName, userStoreManager, tenantDomain, unlockTimePropertyValue,
                                    unlockTimeRatio, currentFailedLoginLockouts);
                            log.debug(msg);
                        }
                        /*
                         * If account unlock time out is configured, calculates the account unlock time as below.
                         * account unlock time =
                         *      current system time + (account unlock time out configured + account lock time out
                         *      increment factor raised to the power of failed login attempt cycles)
                         */
                        unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow
                                (unlockTimeRatio, currentFailedLoginLockouts));
                        accountLockDuration = unlockTimePropertyValue / 60000;
                        unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
                        newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, Long.toString(unlockTime));
                    }
                }
                currentFailedLoginLockouts += 1;

                if (currentFailedLoginLockouts > 1) {
                    boolean notificationOnLockIncrement = getNotificationOnLockIncrementConfig(tenantDomain);
                    // If the 'NOTIFY_ON_LOCK_DURATION_INCREMENT' config is enabled, trigger the account lock email
                    // notification with the new lock duration information.
                    if (notificationOnLockIncrement) {
                        Property identityProperty = new Property();
                        identityProperty.setName(AccountConstants.ACCOUNT_UNLOCK_TIME);
                        identityProperty.setValue(Long.toString(accountLockDuration));
                        triggerNotificationOnAccountLockIncrement(userName, userStoreDomainName,
                                claimValues.get(AccountConstants.ACCOUNT_STATE_CLAIM_URI), tenantDomain,
                                new Property[]{identityProperty});
                    }
                }

                newClaims.put(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, Integer.toString(currentFailedLoginLockouts));
                newClaims.put(failedAttemptsClaim, "0");

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                        USER_IS_LOCKED + ":" + AccountConstants.MAX_ATTEMPTS_EXCEEDED, currentFailedAttempts,
                        maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.USER_ACCOUNT_STATE, USER_IS_LOCKED);
                if (log.isDebugEnabled()) {
                    log.debug(String.format("User: %s is locked due to exceeded the maximum allowed failed " +
                            "attempts", userName));
                }
                IdentityUtil.threadLocalProperties.get().put(AccountConstants.ADMIN_INITIATED, false);
            } else {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(INVALID_CREDENTIAL,
                        currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            }
            try {
                setUserClaims(userName, tenantDomain, userStoreManager, newClaims);
            } catch (NumberFormatException e) {
                throw new AccountLockException("Error occurred while parsing config values", e);
            }
            if (isMaxAttemptsExceeded) {
                /*
                 * Setting the error message context with locked reason again here, as it is overridden when setting
                 * user claims by org.wso2.carbon.identity.governance.listener.IdentityStoreEventListener .
                 */
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                        USER_IS_LOCKED + ":" + AccountConstants.MAX_ATTEMPTS_EXCEEDED, currentFailedAttempts,
                        maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            }
        }
        return true;
    }

    private boolean handleLockedAccount(String userName, UserStoreManager userStoreManager, String userStoreDomainName,
                              String tenantDomain, Map<String, String> claimValues)
            throws AccountLockException {

        long unlockTime = getUnlockTime(claimValues.get(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM));

        if (isAccountLock(claimValues.get(AccountConstants.ACCOUNT_LOCKED_CLAIM))) {
            if (AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)) {
                if (log.isDebugEnabled()) {
                    String bypassMsg = String.format("Account locking is bypassed as lock bypass role: %s is " +
                            "assigned to the user %s", AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE, userName);
                    log.debug(bypassMsg);
                }
                return true;
            }
            /*
             * User account is locked. If the current time is not exceeded user unlock time, send an error message
             * saying user is locked, otherwise users can try to authenticate and unlock their account upon a
             * successful authentication.
             */
            if (System.currentTimeMillis() < unlockTime || unlockTime == 0) {
                String accountLockedReason = claimValues.get(AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI);
                boolean isAdminInitiatedAccountLock = ADMIN_INITIATED.toString().equals(accountLockedReason);

                String message;
                if (StringUtils.isNotBlank(userStoreDomainName)) {
                    message = String.format("Account is locked for user: %s in user store: %s in tenant: %s. " +
                                    "Cannot login until the account is unlocked.", AccountUtil.maskIfRequired(userName),
                            userStoreDomainName, tenantDomain);
                    if (isAdminInitiatedAccountLock) {
                        message = String.format("Account is locked by admin for user: %s in user store: %s in " +
                                        "tenant: %s. Cannot login until the account is unlocked.",
                                AccountUtil.maskIfRequired(userName), userStoreDomainName, tenantDomain);
                    }
                } else {
                    message = String.format("Account is locked for user: %s in tenant: %s. Cannot login until the " +
                            "account is unlocked.", AccountUtil.maskIfRequired(userName), tenantDomain);
                    if (isAdminInitiatedAccountLock) {
                        message = String.format("Account is locked by admin for user: %s in tenant: %s. " +
                                        "Cannot login until the account is unlocked.", AccountUtil.maskIfRequired(
                                        userName),
                                tenantDomain);
                    }
                }
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }

                if (isAdminInitiatedAccountLock) {
                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                            USER_IS_LOCKED + ":" + AccountConstants.ADMIN_INITIATED);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                    throw new AccountLockException(USER_IS_LOCKED + ":" + AccountConstants.ADMIN_INITIATED, message);
                }

                if (MAX_ATTEMPTS_EXCEEDED.toString().equals(accountLockedReason)) {
                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                            USER_IS_LOCKED + ":" + AccountConstants.MAX_ATTEMPTS_EXCEEDED);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                    throw new AccountLockException(USER_IS_LOCKED, message);
                }

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(USER_IS_LOCKED);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                throw new AccountLockException(USER_IS_LOCKED, message);
            }
        }
        return false;
    }

    /**
     * Check whether the account can be unlocked by checking whether account unlock time is exceeded or account bypass
     * role is attached.
     *
     * @param userName              Name of the logged in user.
     * @param userStoreManager      User store.
     * @param currentFailedAttempts Number of fail attempts.
     * @param unlockTime            Time which account can be unlocked.
     * @param accountLockClaim      Current lock claim value.
     * @return Whether the account can be unlocked.
     * @throws AccountLockException
     */
    private boolean isUserUnlockable(String userName, UserStoreManager userStoreManager, int currentFailedAttempts,
                                     long unlockTime, String accountLockClaim) throws AccountLockException {

        return (unlockTime != 0 && System.currentTimeMillis() >= unlockTime)
                || currentFailedAttempts > 0
                || ((Boolean.parseBoolean(accountLockClaim)
                && AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)));
    }

    protected boolean handlePreSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                  String userStoreDomainName, String tenantDomain,
                                                  Property[] identityProperties, int maximumFailedAttempts,
                                                  String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        if (lockedState.get() != null) {
            return true;
        }
        boolean existingAccountLockedValue;
        Map<String, String> claimValues = null;

        try {
            claimValues = userStoreManager.getUserClaimValues(userName,
                    new String[]{AccountConstants.ACCOUNT_LOCKED_CLAIM, AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM,
                            AccountConstants.ACCOUNT_STATE_CLAIM_URI},
                    UserCoreConstants.DEFAULT_PROFILE);
            existingAccountLockedValue = Boolean.parseBoolean(claimValues.get(AccountConstants.ACCOUNT_LOCKED_CLAIM));
            IdentityUtil.threadLocalProperties.get().put(AccountConstants.PREVIOUS_ACCOUNT_STATE,
                    claimValues.get(AccountConstants.ACCOUNT_STATE_CLAIM_URI));
        } catch (UserStoreException e) {
            throw new AccountLockException(String.format("Error occurred while retrieving %s and %s claim values",
                    AccountConstants.ACCOUNT_LOCKED_CLAIM, AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM), e);
        }
        String newStateString = ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS")).get(ACCOUNT_LOCKED_CLAIM);
        if (StringUtils.isNotBlank(newStateString)) {
            Boolean newAccountLockedValue = Boolean.parseBoolean(
                    ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS")).get(ACCOUNT_LOCKED_CLAIM));
            if (existingAccountLockedValue != newAccountLockedValue) {
                String accountLockedEventName;
                if (existingAccountLockedValue) {
                    accountLockedEventName = IdentityEventConstants.Event.PRE_UNLOCK_ACCOUNT;
                    lockedState.set(lockedStates.UNLOCKED_MODIFIED.toString());
                    if (event.getEventProperties().get("USER_CLAIMS") != null) {
                        ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS")).put(AccountConstants.
                                ACCOUNT_LOCKED_REASON_CLAIM_URI, StringUtils.EMPTY);
                        if (StringUtils.isNotEmpty(claimValues.get(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM))) {
                            ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS"))
                                    .put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                        }
                    }
                } else {
                    accountLockedEventName = IdentityEventConstants.Event.PRE_LOCK_ACCOUNT;
                    lockedState.set(lockedStates.LOCKED_MODIFIED.toString());
                    IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.USER_ACCOUNT_STATE,
                            USER_IS_LOCKED);
                }
                publishPreAccountLockedEvent(accountLockedEventName, event.getEventProperties());
            } else {
                if (existingAccountLockedValue) {
                    lockedState.set(lockedStates.LOCKED_UNMODIFIED.toString());
                } else {
                    lockedState.set(lockedStates.UNLOCKED_UNMODIFIED.toString());
                }
            }
        } else {
            if (existingAccountLockedValue) {
                lockedState.set(lockedStates.LOCKED_UNMODIFIED.toString());
            } else {
                lockedState.set(lockedStates.UNLOCKED_UNMODIFIED.toString());
            }
        }
        return true;
    }

    protected boolean handlePostSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                   String userStoreDomainName, String tenantDomain,
                                                   Property[] identityProperties, int maximumFailedAttempts,
                                                   String accountLockTime, double unlockTimeRatio,
                                                   boolean adminForcedPasswordResetLockNotificationEnabled,
                                                   boolean adminForcedPasswordResetUnlockNotificationEnabled)
            throws AccountLockException {

        String newAccountState = null;
        Map<String, String> userClaims = new HashMap<>();
        Map<String, String> claimValues = null;

        try {
            claimValues = userStoreManager.getUserClaimValues(userName,
                    new String[]{AccountConstants.ACCOUNT_STATE_CLAIM_URI, AccountConstants.ACCOUNT_DISABLED_CLAIM,
                            AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                            AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);

        } catch (UserStoreException e) {
            throw new AccountLockException(
                    String.format("Error occurred while retrieving %s, %s, %s and %s claim values",
                            AccountConstants.ACCOUNT_STATE_CLAIM_URI, AccountConstants.ACCOUNT_DISABLED_CLAIM,
                            AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                            AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM), e);
        }

        try {
            boolean notificationInternallyManage = true;

            String existingAccountStateClaimValue = getAccountState(claimValues.get(AccountConstants
                    .ACCOUNT_STATE_CLAIM_URI), tenantDomain);
            String previousAccountStateClaimValue = StringUtils.EMPTY;
            if (IdentityUtil.threadLocalProperties.get().get(AccountConstants.PREVIOUS_ACCOUNT_STATE) != null) {
                previousAccountStateClaimValue =
                        getAccountState(
                                (String) IdentityUtil.threadLocalProperties.get()
                                        .get(AccountConstants.PREVIOUS_ACCOUNT_STATE),
                                tenantDomain);
            }
            try {
                notificationInternallyManage = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                        .NOTIFICATION_INTERNALLY_MANAGE, tenantDomain));
            } catch (IdentityEventException e) {
                log.warn("Error while reading Notification internally manage property in account lock handler");
                if (log.isDebugEnabled()) {
                    log.debug("Error while reading Notification internally manage property in account lock handler", e);
                }
            }
            boolean isAdminInitiated = true;
            if (IdentityUtil.threadLocalProperties.get().get(AccountConstants.ADMIN_INITIATED) != null) {
                isAdminInitiated = (boolean) IdentityUtil.threadLocalProperties.get()
                        .get(AccountConstants.ADMIN_INITIATED);
            }

            if (lockedStates.UNLOCKED_MODIFIED.toString().equals(lockedState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is unlocked", userName));
                }
                String emailTemplateTypeAccUnlocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED;
                if (notificationInternallyManage) {
                    if (isAdminInitiated) {
                        if (AccountUtil
                                .isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_ADMIN_TRIGGERED,
                                        tenantDomain)) {
                            emailTemplateTypeAccUnlocked =
                                    AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_ADMIN_TRIGGERED;
                        }
                    } else {
                        if (AccountUtil.isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_TIME_BASED,
                                tenantDomain)) {
                            emailTemplateTypeAccUnlocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_TIME_BASED;
                        }
                    }
                    boolean isPendingSelfRegistration =
                            AccountConstants.PENDING_SELF_REGISTRATION.equals(previousAccountStateClaimValue);
                    boolean isPendingLiteRegistration =
                            AccountConstants.PENDING_LITE_REGISTRATION.equals(previousAccountStateClaimValue);
                    boolean isPendingAskPassword =
                            AccountConstants.PENDING_ASK_PASSWORD.equals(previousAccountStateClaimValue);
                    boolean isPendingEmailVerification =
                            AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue);
                    boolean disableUnlockStateInEmailVerification =
                            Boolean.parseBoolean(
                                    IdentityUtil.getProperty(AccountConstants.DISABLE_ACCOUNT_UNLOCK_NOTIFICATION));
                    if (IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET
                            .equals(previousAccountStateClaimValue)) {
                        if (adminForcedPasswordResetUnlockNotificationEnabled) {
                            triggerNotification(userName, userStoreDomainName, tenantDomain, identityProperties,
                                    emailTemplateTypeAccUnlocked);
                        }
                    } else if (!isPendingSelfRegistration && !isPendingLiteRegistration &&
                            !(isPendingAskPassword && isAccountLockOnCreationEnabled(tenantDomain)) &&
                            !(isPendingEmailVerification && disableUnlockStateInEmailVerification)) {
                        triggerNotification(userName, userStoreDomainName, tenantDomain, identityProperties,
                                emailTemplateTypeAccUnlocked);
                    }
                }
                newAccountState = buildAccountState(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED, tenantDomain,
                        claimValues.get(AccountConstants.ACCOUNT_DISABLED_CLAIM));
                publishPostAccountLockedEvent(IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT,
                        event.getEventProperties(), true);
                auditAccountLock(AuditConstants.ACCOUNT_UNLOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, true, claimValues);
            } else if (lockedStates.LOCKED_MODIFIED.toString().equals(lockedState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is locked", userName));
                }
                String emailTemplateTypeAccLocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED;
                if (isAdminInitiated && StringUtils.isBlank(claimValues.get(
                        AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI))) {
                    userClaims.put(AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                            IdentityMgtConstants.LockedReason.ADMIN_INITIATED.toString());
                    if (StringUtils.isNotBlank(claimValues.get(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM))) {
                        userClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                    }
                }
                if (notificationInternallyManage) {
                    Property[] properties = null;
                    if (isAdminInitiated) {
                        if (AccountUtil.isTemplateExists(
                                AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_ADMIN_TRIGGERED, tenantDomain)) {
                            emailTemplateTypeAccLocked =
                                    AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_ADMIN_TRIGGERED;
                        }
                    } else {
                        if (AccountUtil.isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT,
                                tenantDomain)) {
                            emailTemplateTypeAccLocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT;
                            Property identityProperty = new Property();
                            identityProperty.setName(AccountConstants.ACCOUNT_UNLOCK_TIME);
                            identityProperty.setValue(getAccountLockDuration(claimValues.get(AccountConstants
                                    .ACCOUNT_UNLOCK_TIME_CLAIM)));
                            properties = new Property[]{identityProperty};
                        }
                    }

                    // Check if the account is in PENDING_AFUPR state.
                    if (IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET.equals(
                            existingAccountStateClaimValue)) {
                        // Send notification if the unlock notification enabled.
                        if (adminForcedPasswordResetLockNotificationEnabled) {
                            triggerNotification(userName, userStoreDomainName, tenantDomain, identityProperties,
                                    emailTemplateTypeAccLocked);
                        }
                        // Send locked email only if the accountState claim value doesn't have PENDING_SR, PENDING_EV
                        // PENDING_LR or PENDING_AP with EmailVerification.LockOnCreation enabled.
                    } else if (!AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                            !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue) &&
                            !AccountConstants.PENDING_LITE_REGISTRATION.equals(existingAccountStateClaimValue) &&
                            !(AccountConstants.PENDING_ASK_PASSWORD.equals(existingAccountStateClaimValue) &&
                                    isAccountLockOnCreationEnabled(tenantDomain))) {
                        triggerNotification(userName, userStoreDomainName, tenantDomain, properties,
                                emailTemplateTypeAccLocked);
                    }
                }
                /* Set new account state only if the accountState claim value is neither PENDING_SR, PENDING_EV,
                PENDING_LR, PENDING_FUPR nor PENDING_AP. */
                if (!AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_LITE_REGISTRATION.equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET
                                .equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_ASK_PASSWORD.equals(existingAccountStateClaimValue)) {
                    newAccountState = buildAccountState(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED, tenantDomain,
                            claimValues.get(AccountConstants.ACCOUNT_DISABLED_CLAIM));
                }
                publishPostAccountLockedEvent(IdentityEventConstants.Event.POST_LOCK_ACCOUNT, event.getEventProperties()
                        , true);
                auditAccountLock(AuditConstants.ACCOUNT_LOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, true, claimValues);
            } else if (lockedStates.LOCKED_UNMODIFIED.toString().equals(lockedState.get())) {
                auditAccountLock(AuditConstants.ACCOUNT_LOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, false, claimValues);
            } else if (lockedStates.UNLOCKED_UNMODIFIED.toString().equals(lockedState.get())) {
                auditAccountLock(AuditConstants.ACCOUNT_UNLOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, false, claimValues);
            }
        } finally {
            lockedState.remove();
            IdentityUtil.threadLocalProperties.get().remove(AccountConstants.ADMIN_INITIATED);
            IdentityUtil.threadLocalProperties.get().remove(AccountConstants.PREVIOUS_ACCOUNT_STATE);
        }
        if (StringUtils.isNotEmpty(newAccountState)) {
            userClaims.put(AccountConstants.ACCOUNT_STATE_CLAIM_URI, newAccountState);
            setUserClaims(userName, tenantDomain, userStoreManager, userClaims);
        } else if (!userClaims.isEmpty()) {
            setUserClaims(userName, tenantDomain, userStoreManager, userClaims);
        }
        return true;
    }

    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(AccountConstants.ACCOUNT_LOCK_MAX_FAILED_ATTEMPTS_PROPERTY);
        properties.add(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY);
        properties.add(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY);
        properties.add(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY);
        properties.add(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE);
        properties.add(AccountConstants.NOTIFY_ON_LOCK_DURATION_INCREMENT);

        return properties.toArray(new String[properties.size()]);
    }

    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        return configs.getModuleProperties();
    }

    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {
        return null;
    }

    /**
     * Triggers notification.
     * @deprecated Use {@link #triggerNotification(String, String, String, Property[], String)}
     *
     * @param event                 Event.
     * @param userName              Username.
     * @param userStoreManager      User store manager.
     * @param userStoreDomainName   User store domain name.
     * @param tenantDomain          Tenant domain.
     * @param identityProperties    Identity properties.
     * @param notificationEvent     Notification event.
     * @throws AccountLockException Account lock exception.
     */
    @Deprecated
    protected void triggerNotification(Event event, String userName, UserStoreManager userStoreManager,
                                       String userStoreDomainName, String tenantDomain,
                                       Property[] identityProperties, String notificationEvent) throws
            AccountLockException {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put("TEMPLATE_TYPE", notificationEvent);

        if (AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT.equals(notificationEvent) &&
                ArrayUtils.isNotEmpty(identityProperties)) {
            for (Property property : identityProperties) {
                if (AccountConstants.ACCOUNT_UNLOCK_TIME.equals(property.getName())) {
                    properties.put(AccountConstants.LOCK_DURATION_EMAIL_TEMPLATE_PARAMETER, property.getValue());
                    break;
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AccountServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (Exception e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage();
            /*
            We are not throwing any exception from here, because this event notification should not break the main
            flow.
             */
            log.warn(errorMsg);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
        }
    }

    /**
     * Triggers notification.
     *
     * @param userName              Username.
     * @param userStoreDomainName   User store domain name.
     * @param tenantDomain          Tenant domain.
     * @param identityProperties    Identity properties.
     * @param notificationEvent     Notification event.
     * @throws AccountLockException Account lock exception.
     */
    protected void triggerNotification(String userName, String userStoreDomainName, String tenantDomain,
                                       Property[] identityProperties, String notificationEvent)
            throws AccountLockException {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;
        String serviceProviderUUID = (String) IdentityUtil.threadLocalProperties.get().get(IdentityEventConstants.EventProperty.SERVICE_PROVIDER_UUID);

        HashMap<String, Object> properties = new HashMap<>();
        if (serviceProviderUUID != null && !serviceProviderUUID.isEmpty()) {
            properties.put(IdentityEventConstants.EventProperty.SERVICE_PROVIDER_UUID, serviceProviderUUID);
        }
        properties.put(USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put("TEMPLATE_TYPE", notificationEvent);

        if (AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT.equals(notificationEvent) &&
                ArrayUtils.isNotEmpty(identityProperties)) {
            for (Property property : identityProperties) {
                if (AccountConstants.ACCOUNT_UNLOCK_TIME.equals(property.getName())) {
                    properties.put(AccountConstants.LOCK_DURATION_EMAIL_TEMPLATE_PARAMETER, property.getValue());
                    break;
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AccountServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (Exception e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage();
            /*
            We are not throwing any exception from here, because this event notification should not break the main
            flow.
             */
            log.warn(errorMsg);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
        }
    }

    /**
     * Retrieve unlock time from the user store.
     * @deprecated use {@link #getUnlockTime(String accountLockTimeUserClaimValue)} instead.
     *
     * @param userName          Username of the user.
     * @param userStoreManager  UserStoreManager of the user.
     * @return Unlock time of the user.
     * @throws AccountLockException Error while retrieving unlock time.
     */
    @Deprecated
    protected long getUnlockTime(String userName, UserStoreManager userStoreManager) throws AccountLockException {

        long unlockTime = 0;

        try {
            Map<String, String> values = userStoreManager.getUserClaimValues(userName, new String[]{
                    ACCOUNT_UNLOCK_TIME_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            String userClaimValue = values.get(ACCOUNT_UNLOCK_TIME_CLAIM);

            if (NumberUtils.isNumber(userClaimValue)) {
                unlockTime = Long.parseLong(userClaimValue);
            }
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + ACCOUNT_UNLOCK_TIME_CLAIM +
                    " claim value", e);
        }
        return unlockTime;
    }

    /**
     * Retrieve unlock time from the claim value.
     *
     * @param accountUnlockTimeUserClaimValue User Account unlock time value.
     * @return Numerical value of user account unlock time.
     */
    protected long getUnlockTime(String accountUnlockTimeUserClaimValue) {

        long unlockTime = 0;
        if (NumberUtils.isNumber(accountUnlockTimeUserClaimValue)) {
            unlockTime = Long.parseLong(accountUnlockTimeUserClaimValue);
        }
        return unlockTime;
    }

    /**
     * Retrieve account lock state from userStore.
     * @deprecated use {@link #isAccountLock(String accountLockedClaim)} instead.
     *
     * @param userName         Current username.
     * @param userStoreManager User store.
     * @return State whether current user is a privileged user.
     * @throws AccountLockException If an error occurred while retrieving account locked claim value.
     */
    protected boolean isAccountLock(String userName, UserStoreManager userStoreManager) throws AccountLockException {

        String accountLockedClaim;
        try {
            Map<String, String> values = userStoreManager.getUserClaimValues(userName, new String[]{
                    ACCOUNT_LOCKED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            accountLockedClaim = values.get(ACCOUNT_LOCKED_CLAIM);

        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + ACCOUNT_LOCKED_CLAIM
                    + " claim value", e);
        }
        return Boolean.parseBoolean(accountLockedClaim);
    }

    /**
     * Retrieve account lock state from the claim value.
     *
     * @param accountLockedClaim User Account locked or not value.
     * @return Boolean value of User Account locked state.
     */
    protected boolean isAccountLock(String accountLockedClaim) {

        return Boolean.parseBoolean(accountLockedClaim);
    }

    private boolean isUserExistsInDomain(UserStoreManager userStoreManager, String userName)
            throws AccountLockException {

        boolean isExists = false;
        try {
            if (userStoreManager.isExistingUser(userName)) {
                isExists = true;
            }
        } catch (UserStoreException e) {
            throw new AccountLockException(
                    "Error occurred while check user existence: " + AccountUtil.maskIfRequired(userName), e);
        }
        return isExists;
    }

    private boolean isAuthPolicyAccountExistCheck() {

        return Boolean.parseBoolean(IdentityUtil.getProperty("AuthenticationPolicy.CheckAccountExist"));
    }

    /**
     * Build user account state.
     *
     * @param state                     Whether the account is locker or not.
     * @param tenantDomain              Tenant domain.
     * @param accountDisabledClaimValue Whether the account is disabled or not.
     * @return account state.
     * @throws AccountLockException AccountLockException.
     */
    private String buildAccountState(String state, String tenantDomain, String accountDisabledClaimValue)
            throws AccountLockException {

        boolean isAccountStateClaimExist = AccountUtil.isAccountStateClaimExisting(tenantDomain);
        String newAccountstate = null;
        if (isAccountStateClaimExist) {
            if (isAccountDisabled(accountDisabledClaimValue)) {
                // If accountDisabled claim is true, then set accountState=DISABLED
                newAccountstate = AccountConstants.DISABLED;
            } else if (state.equals(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED)) {
                // If accountDisabled claim is false and accountLocked claim is false, then set
                // accountState=UNLOCKED
                newAccountstate = AccountConstants.UNLOCKED;
            } else if (state.equals(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED)) {
                // If accountDisabled claim is false and accountLocked claim is true, then set
                // accountState=LOCKED
                newAccountstate = AccountConstants.LOCKED;
            }
        }
        return newAccountstate;
    }

    /**
     * Get account state.
     *
     * @param accountStateClaimValue Account state claim value.
     * @param tenantDomain           Tenant domain.
     * @return account state.
     * @throws AccountLockException AccountLockException.
     */
    private String getAccountState(String accountStateClaimValue, String tenantDomain) throws AccountLockException {

        boolean isAccountStateClaimExist = AccountUtil.isAccountStateClaimExisting(tenantDomain);
        if (!isAccountStateClaimExist) {
            accountStateClaimValue = "";
        }
        return accountStateClaimValue;
    }

    /**
     * Check whether the account is disabled or not.
     *
     * @param accountDisabledClaimValue account disabled claim value.
     * @return whether the account is disabled or not.
     */
    private boolean isAccountDisabled(String accountDisabledClaimValue) {

        return Boolean.parseBoolean(accountDisabledClaimValue);
    }

    /**
     * Audit account lock event.
     *
     * @param action              activity
     * @param target              target affected by this activity
     * @param userStoreDomainName Domain name of the userstore
     * @param isAdminInitiated    whether Account lock admin initiated
     * @param errorMsg            if error occurs
     * @param result              Result value
     * @param claims
     */
    private void auditAccountLock(String action, String target, String userStoreDomainName, boolean isAdminInitiated,
                                  String errorMsg, String result, Boolean isModifiedStatus, Map<String, String> claims) {

        JSONObject dataObject = new JSONObject();
        dataObject.put(AuditConstants.REMOTE_ADDRESS_KEY, MDC.get(AuditConstants.REMOTE_ADDRESS_QUERY_KEY));
        dataObject.put(AuditConstants.USER_AGENT_KEY, MDC.get(AuditConstants.USER_AGENT_QUERY_KEY));
        dataObject.put(AuditConstants.SERVICE_PROVIDER_KEY, MDC.get(AuditConstants.SERVICE_PROVIDER_QUERY_KEY));
        dataObject.put(AccountConstants.ADMIN_INITIATED, isAdminInitiated);
        dataObject.put(AuditConstants.USER_STORE_DOMAIN, userStoreDomainName);
        dataObject.put(AuditConstants.IS_MODIFIED_STATUS, isModifiedStatus);

        if (claims != null) {
            dataObject.put(AuditConstants.USER_IDENTITY_CLAIMS, new JSONObject(claims));
        }
        if (AuditConstants.AUDIT_FAILED.equals(result)) {
            dataObject.put(AuditConstants.ERROR_MESSAGE_KEY, errorMsg);
        }
        AccountUtil.createAuditMessage(action, target, dataObject, result);
    }

    private void publishPreAccountLockedEvent(String accountLockedEventName, Map<String, Object> map) throws
            AccountLockException {

        AccountUtil.publishEvent(accountLockedEventName, AccountUtil.cloneMap(map));
    }

    private void publishPostAccountLockedEvent(String accountLockedEventName, Map<String, Object> map, boolean
            isLockPropertySuccessfullyModified) throws AccountLockException {

        Map<String, Object> eventProperties = AccountUtil.cloneMap(map);
        if (MapUtils.isNotEmpty(eventProperties)) {
            eventProperties.put(IdentityEventConstants.EventProperty.UPDATED_LOCKED_STATUS,
                    isLockPropertySuccessfullyModified);
        }
        AccountUtil.publishEvent(accountLockedEventName, eventProperties);
    }

    /**
     * Update user claim values.
     *
     * @param username         Username.
     * @param tenantDomain     Tenant domain.
     * @param userStoreManager UserStoreManager.
     * @param claimsList       Claims Map.
     * @throws AccountLockException If an error occurred.
     */
    private void setUserClaims(String username, String tenantDomain, UserStoreManager userStoreManager,
                               Map<String, String> claimsList) throws AccountLockException {

        try {
            userStoreManager.setUserClaimValues(username, claimsList, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            throw new AccountLockException(String.format("Error occurred while updating the user claims " +
                    "for user: %s in tenant: %s", AccountUtil.maskIfRequired(username), tenantDomain), e);
        }
    }

    /**
     * Get the account lock failed attempt count claim from the event properties. If no claim is specified, the
     * default claim will be used.
     *
     * @param authenticator   Authenticator Name.
     * @param eventProperties Event properties.
     * @return Account lock failed attempt count claim.
     */
    private String resolveFailedLoginAttemptsCounterClaim(String authenticator, Map<String, Object> eventProperties) {

        if (StringUtils.isBlank(authenticator)) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No authenticator has specified. Therefore, using the default claim: %s as " +
                                "failed attempt counting claim: %s", authenticator, FAILED_LOGIN_ATTEMPTS_CLAIM));
            }
        }
        if (eventProperties.get(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM) == null ||
                StringUtils.isBlank(String.valueOf(eventProperties.get(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM)))) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No failed attempt count claim defined for authenticator: %s. Therefore, " +
                        "using the default claim: %s as failed attempt counting claim",
                        authenticator, FAILED_LOGIN_ATTEMPTS_CLAIM));
            }
            return FAILED_LOGIN_ATTEMPTS_CLAIM;
        }
        return String.valueOf(eventProperties.get(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM));
    }

    /**
     * Send email notification to the user when the account lock duration is incremented due to further failed login
     * attempts.
     */
    private void triggerNotificationOnAccountLockIncrement(String userName, String userStoreDomainName,
                                                           String userAccountStateClaimValue, String tenantDomain,
                                                           Property[] identityProperties) throws AccountLockException {

        boolean notificationInternallyManage = true;
        try {
            notificationInternallyManage = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                    .NOTIFICATION_INTERNALLY_MANAGE, tenantDomain));
        } catch (IdentityEventException e) {
            log.warn("Error while reading Notification internally manage property in account lock handler." +
                    e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Error while reading Notification internally manage property in account lock handler", e);
            }
        }

        if (notificationInternallyManage && AccountUtil.isTemplateExists
                (AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT, tenantDomain)) {
            String existingAccountStateClaimValue = getAccountState(userAccountStateClaimValue, tenantDomain);

            // Send locked email only if the accountState claim value doesn't have PENDING_AFUPR, PENDING_SR,
            // PENDING_EV or PENDING_LR.
            if (!IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET.equals(
                    existingAccountStateClaimValue) &&
                    !AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                    !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue) &&
                    !AccountConstants.PENDING_LITE_REGISTRATION.equals(existingAccountStateClaimValue)) {
                triggerNotification(userName, userStoreDomainName, tenantDomain, identityProperties,
                        AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED_FAILED_ATTEMPT);
            }
        }
    }

    /**
     * Calculate account lock duration by considering the unlock time claim and the current time.
     *
     * @param accountUnlockTimeClaim UnlockTime claim value.
     * @return  Lock duration in minutes.
     */
    private String getAccountLockDuration(String accountUnlockTimeClaim) {

        long accountUnlockTime = 0;
        if (StringUtils.isNotEmpty(accountUnlockTimeClaim)) {
            try {
                accountUnlockTime = Long.parseLong(accountUnlockTimeClaim);
            } catch (NumberFormatException e) {
                String errorMsg = "Error occurred while parsing the account locked duration, " +
                        "detail : " + e.getMessage();
                log.warn(errorMsg);
                if (log.isDebugEnabled()) {
                    log.debug(errorMsg, e);
                }
            }
        }
        long userLockedDuration = 0;
        if (accountUnlockTime > 0) {
            userLockedDuration = (long) Math.ceil((accountUnlockTime - System.currentTimeMillis())/60000.0);
        }
        return Long.toString(userLockedDuration);
    }

    /**
     * Get the account lock connector configuration to decide whether to trigger notifications on every lockout cycle.
     *
     * @param tenantDomain  Tenant Domain.
     * @return  Whether the config is enabled not not.
     */
    private boolean getNotificationOnLockIncrementConfig(String tenantDomain) {

        boolean notificationOnLockIncrement = false;
        try {
            notificationOnLockIncrement = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                    .NOTIFY_ON_LOCK_DURATION_INCREMENT, tenantDomain));
        } catch (IdentityEventException e) {
            log.warn("Error while reading notification on lock increment property in account lock handler. "
                    + e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Error while reading notification on lock increment property in account lock " +
                        "handler", e);
            }
        }
        return notificationOnLockIncrement;
    }

    /**
     * Returns whether the EmailVerification.LockOnCreation config is enabled or not.
     *
     * @param tenantDomain Tenant domain.
     * @return Whether the EmailVerification.LockOnCreation config is enabled not.
     * @throws AccountLockException If an unexpected error occurred while retrieving Email Verification properties.
     */
    private boolean isAccountLockOnCreationEnabled(String tenantDomain) throws AccountLockException {

        // Default value of EmailVerification.LockOnCreation is true.
        boolean accountLockOnCreationEnabled = true;
        Property[] emailVerificationProperties;
        try {
            emailVerificationProperties =
                    AccountServiceDataHolder.getInstance().getIdentityGovernanceService()
                            .getConfiguration(new String[]{
                                            AccountConstants.EMAIL_ACCOUNT_LOCK_ON_CREATION},
                                    tenantDomain);
            if (ArrayUtils.isNotEmpty(emailVerificationProperties) &&
                    emailVerificationProperties.length == 1 &&
                    AccountConstants.EMAIL_ACCOUNT_LOCK_ON_CREATION.equals(
                            emailVerificationProperties[0].getName())) {
                accountLockOnCreationEnabled =
                        Boolean.parseBoolean(emailVerificationProperties[0].getValue());
            }
        } catch (IdentityGovernanceException e) {
            throw new AccountLockException("Error while retrieving Email Verification properties.", e);
        }
        return accountLockOnCreationEnabled;
    }
}
