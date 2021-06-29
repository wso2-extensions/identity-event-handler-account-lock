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

package org.wso2.carbon.identity.handler.event.account.lock;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
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
        nameMapping.put(AccountConstants.ACCOUNT_LOCKED_PROPERTY, "Lock user accounts");
        nameMapping.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Maximum failed login attempts");
        nameMapping.put(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Initial account lock duration");
        nameMapping.put(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY, "Account lock duration increment factor");
        nameMapping.put(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE, "Manage notification sending internally");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(AccountConstants.ACCOUNT_LOCKED_PROPERTY, "Lock user accounts on failed login attempts");
        descriptionMapping.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Number of failed login attempts " +
                "allowed until account lock.");
        descriptionMapping.put(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Initial account lock time period in " +
                "minutes. Account will be automatically unlocked after this time period.");
        descriptionMapping.put(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY, "Account lock duration will be " +
                "increased by this factor. Ex: Initial duration: 5m; Increment factor: 2; Next lock duration: 5 x 2 = 10m");
        descriptionMapping.put(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE, "Disable if the client application " +
                "handles notification sending");
        return descriptionMapping;
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 100;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(USER_STORE_MANAGER);
        String userStoreDomainName = AccountUtil.getUserStoreDomainName(userStoreManager);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        Property[] identityProperties;
        boolean accountLockedEnabled = false;
        String accountLockTime = "0";
        int maximumFailedAttempts = 0;
        double unlockTimeRatio = 1;
        String adminPasswordResetAccountLockNotificationProperty = IdentityUtil.getProperty(
                AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_LOCK_NOTIFICATION_ENABLE_PROPERTY);
        boolean adminForcePasswordResetLockNotificationEnabled =
                Boolean.parseBoolean(adminPasswordResetAccountLockNotificationProperty);
        String adminPasswordResetAccountUnlockNotificationProperty = IdentityUtil.getProperty(
                AccountConstants.ADMIN_FORCE_PASSWORD_RESET_ACCOUNT_UNLOCK_NOTIFICATION_ENABLE_PROPERTY);
        boolean adminForcePasswordResetUnlockNotificationEnabled =
                        Boolean.parseBoolean(adminPasswordResetAccountUnlockNotificationProperty);
        try {
            identityProperties = AccountServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving Account Locking Handler properties.", e);
        }
        for (Property identityProperty : identityProperties) {
            if (AccountConstants.ACCOUNT_LOCKED_PROPERTY.equals(identityProperty.getName())) {
                accountLockedEnabled = Boolean.parseBoolean(identityProperty.getValue());
            } else if (AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY.equals(identityProperty.getName())) {
                maximumFailedAttempts = Integer.parseInt(identityProperty.getValue());
            } else if (AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY.equals(identityProperty.getName())) {
                accountLockTime = identityProperty.getValue();
            } else if (AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY.equals(identityProperty.getName())) {
                String value = identityProperty.getValue();
                if (NumberUtils.isNumber(value)) {
                    if (Integer.parseInt(value) > 0) {
                        unlockTimeRatio = Integer.parseInt(value);
                    }
                }
            }
        }

        if (!accountLockedEnabled) {
            if (log.isDebugEnabled()) {
                log.debug("Account lock handler is disabled in tenant: " + tenantDomain);
            }
            return;
        }

        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, userStoreDomainName);
        boolean userExists;
        try {
            userExists = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error in accessing user store", e);
        }
        if (!userExists) {
            return;
        }

        if (IdentityEventConstants.Event.PRE_AUTHENTICATION.equals(event.getEventName())) {
            handlePreAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                    identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
        } else if (IdentityEventConstants.Event.POST_AUTHENTICATION.equals(event.getEventName())) {
            handlePostAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                    identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
        } else if (IdentityEventConstants.Event.PRE_SET_USER_CLAIMS.equals(event.getEventName())) {
            handlePreSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                    identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
        } else if (IdentityEventConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName())) {
            PrivilegedCarbonContext.startTenantFlow();
            try {
                PrivilegedCarbonContext.getThreadLocalCarbonContext().
                        setTenantDomain(tenantDomain, true);
                handlePostSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                        identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio,
                        adminForcePasswordResetLockNotificationEnabled,
                        adminForcePasswordResetUnlockNotificationEnabled);
            } finally {
                PrivilegedCarbonContext.endTenantFlow();
            }
        }
    }

    protected boolean handlePreAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                              String userStoreDomainName, String tenantDomain,
                                              Property[] identityProperties, int maximumFailedAttempts,
                                              String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        if (isAuthPolicyAccountExistCheck() && !isUserExistsInDomain(userStoreManager, userName)) {
            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants
                    .ErrorCode.USER_DOES_NOT_EXIST);
            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
        }

        return true;
    }

    protected boolean handlePostAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                               String userStoreDomainName, String tenantDomain,
                                               Property[] identityProperties, int maximumFailedAttempts,
                                               String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        long unlockTime = getUnlockTime(userName, userStoreManager);

        if (isAccountLock(userName, userStoreManager)) {
            if (AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)) {
                if (log.isDebugEnabled()) {
                    String bypassMsg = String.format("Account locking is bypassed as lock bypass role: %s is " +
                            "assigned to the user %s", AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE, userName);
                    log.debug(bypassMsg);
                }
                return true;
            }
            /*
            User account is locked. If the current time is not exceeded user unlock time, send a error message
            saying user is locked, otherwise users can try to authenticate and unlock their account upon a
            successful authentication.
             */
            if (System.currentTimeMillis() < unlockTime || unlockTime == 0) {
                String message;
                if (StringUtils.isNotBlank(userStoreDomainName)) {
                    message = String.format("Account is locked for user: %s in user store: %s in tenant: %s. " +
                            "Cannot login until the account is unlocked.", userName, userStoreDomainName, tenantDomain);
                } else {
                    message = String.format("Account is locked for user: %s in tenant: %s. Cannot login until the " +
                            "account is unlocked.", userName, tenantDomain);
                }
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(USER_IS_LOCKED);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                throw new AccountLockException(USER_IS_LOCKED, message);
            }
        }

        Map<String, Object> eventProperties = event.getEventProperties();
        String authenticator = String.valueOf(eventProperties.get(AUTHENTICATOR_NAME));
        // Resolve the claim which stores failed attempts depending on the authenticator.
        String failedAttemptsClaim = resolveFailedLoginAttemptsCounterClaim(authenticator, eventProperties);

        int currentFailedAttempts = 0;
        int currentFailedLoginLockouts = 0;

        // Get the account locking related claims from the user store.
        Map<String, String> claimValues = getUserClaimsFromUserStore(userName, tenantDomain, userStoreManager,
                new String[]{FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, failedAttemptsClaim, ACCOUNT_LOCKED_CLAIM});
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

            // User is authenticated, Need to check the unlock time to verify whether the user is previously locked.
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
                newClaims.put(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");
                IdentityUtil.threadLocalProperties.get().put(AccountConstants.ADMIN_INITIATED, false);
            }
            setUserClaims(userName, tenantDomain, userStoreManager, newClaims);
        } else {
            // User authentication failed.
            currentFailedAttempts += 1;
            newClaims.put(failedAttemptsClaim, Integer.toString(currentFailedAttempts));
            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_BEFORE_SUCCESS_CLAIM, "0");

            if (AccountUtil.isAccountLockByPassForUser(userStoreManager, userName)) {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(INVALID_CREDENTIAL,
                                currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                if (log.isDebugEnabled()) {
                    log.debug("Login attempt failed. Bypassing account locking for user: "+ userName);
                }
                return true;
            } else if (currentFailedAttempts >= maximumFailedAttempts) {
                // Current failed attempts exceeded maximum allowed attempts. So user should be locked.
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
                        unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
                        newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, Long.toString(unlockTime));
                    }
                }
                currentFailedLoginLockouts += 1;
                newClaims.put(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, Integer.toString(currentFailedLoginLockouts));
                newClaims.put(failedAttemptsClaim, "0");

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(USER_IS_LOCKED,
                        currentFailedAttempts, maximumFailedAttempts);
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
        }
        return true;
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
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                    ACCOUNT_LOCKED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            existingAccountLockedValue = Boolean.parseBoolean(claimValues.get(ACCOUNT_LOCKED_CLAIM));

        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + ACCOUNT_LOCKED_CLAIM + " claim value", e);
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
                        if (StringUtils.isNotEmpty(getClaimValue(userName, userStoreManager,
                                AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM))) {
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
        try {
            boolean notificationInternallyManage = true;

            String existingAccountStateClaimValue = getAccountState(userStoreManager, tenantDomain, userName);
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
                            emailTemplateTypeAccUnlocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_ADMIN_TRIGGERED;
                        }
                    } else {
                        if (AccountUtil.isTemplateExists(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_TIME_BASED,
                                tenantDomain)) {
                            emailTemplateTypeAccUnlocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED_TIME_BASED;
                        }
                    }
                    boolean isPendingSelfRegistration =
                            AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue);
                    boolean isPendingLiteRegistration =
                            AccountConstants.PENDING_LITE_REGISTRATION.equals(existingAccountStateClaimValue);
                    if (IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET
                            .equals(existingAccountStateClaimValue)) {
                        if (adminForcedPasswordResetUnlockNotificationEnabled) {
                            triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, identityProperties,
                                    emailTemplateTypeAccUnlocked);
                        }
                    } else if (!isPendingSelfRegistration && !isPendingLiteRegistration) {
                        triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, identityProperties,
                                emailTemplateTypeAccUnlocked);
                    }
                }
                newAccountState = buildAccountState(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED, tenantDomain,
                        userStoreManager, userName);
                publishPostAccountLockedEvent(IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT,
                        event.getEventProperties(), true);
                auditAccountLock(AuditConstants.ACCOUNT_UNLOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, true);
            } else if (lockedStates.LOCKED_MODIFIED.toString().equals(lockedState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is locked", userName));
                }
                String emailTemplateTypeAccLocked = AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED;
                if (isAdminInitiated && StringUtils.isBlank(getClaimValue(userName, userStoreManager,
                        AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI))) {
                    userClaims.put(AccountConstants.ACCOUNT_LOCKED_REASON_CLAIM_URI,
                            IdentityMgtConstants.LockedReason.ADMIN_INITIATED.toString());
                    if (StringUtils.isNotEmpty(
                            getClaimValue(userName, userStoreManager, AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM))) {
                        userClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                    }
                }
                if (notificationInternallyManage) {
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
                        }
                    }

                    // Check if the account is in PENDING_AFUPR state.
                    if (IdentityMgtConstants.AccountStates.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET.equals(
                            existingAccountStateClaimValue)) {
                        // Send notification if the unlock notification enabled.
                        if (adminForcedPasswordResetLockNotificationEnabled) {
                            triggerNotification(event, userName, userStoreManager, userStoreDomainName,
                                    tenantDomain, identityProperties, emailTemplateTypeAccLocked);
                        }
                        // Send locked email only if the accountState claim value doesn't have PENDIG_SR, PENDING_EV
                        // or PENDING_LR.
                    } else if (!AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                            !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue) &&
                            !AccountConstants.PENDING_LITE_REGISTRATION.equals(existingAccountStateClaimValue)) {
                        triggerNotification(event, userName, userStoreManager, userStoreDomainName,
                                tenantDomain, identityProperties, emailTemplateTypeAccLocked);
                    }
                }
                /* Set new account state only if the accountState claim value is neither PENDING_SR, PENDING_EV,
                PENDING_LR nor PENDING_FUPR. */
                if (!AccountConstants.PENDING_SELF_REGISTRATION.equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_EMAIL_VERIFICATION.equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_LITE_REGISTRATION.equals(existingAccountStateClaimValue) &&
                        !AccountConstants.PENDING_ADMIN_FORCED_USER_PASSWORD_RESET
                                .equals(existingAccountStateClaimValue)) {
                    newAccountState = buildAccountState(AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED,
                            tenantDomain, userStoreManager, userName);
                }
                publishPostAccountLockedEvent(IdentityEventConstants.Event.POST_LOCK_ACCOUNT, event.getEventProperties()
                        , true);
                auditAccountLock(AuditConstants.ACCOUNT_LOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, true);
            } else if (lockedStates.LOCKED_UNMODIFIED.toString().equals(lockedState.get())) {
                auditAccountLock(AuditConstants.ACCOUNT_LOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, false);
            } else if (lockedStates.UNLOCKED_UNMODIFIED.toString().equals(lockedState.get())) {
                auditAccountLock(AuditConstants.ACCOUNT_UNLOCKED, userName, userStoreDomainName, isAdminInitiated,
                        null, AuditConstants.AUDIT_SUCCESS, false);
            }
        } finally {
            lockedState.remove();
            IdentityUtil.threadLocalProperties.get().remove(AccountConstants.ADMIN_INITIATED);
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
        properties.add(AccountConstants.ACCOUNT_LOCKED_PROPERTY);
        properties.add(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY);
        properties.add(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY);
        properties.add(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY);
        properties.add(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE);

        return properties.toArray(new String[properties.size()]);
    }

    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        return configs.getModuleProperties();
    }

    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {
        return null;
    }

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
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AccountServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (Exception e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage();
            //We are not throwing any exception from here, because this event notification should not break the main
            // flow.
            log.warn(errorMsg);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
        }
    }

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

    private boolean isUserExistsInDomain(UserStoreManager userStoreManager, String userName)
            throws AccountLockException {

        boolean isExists = false;
        try {
            if (userStoreManager.isExistingUser(userName)) {
                isExists = true;
            }
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while check user existence: " + userName, e);
        }
        return isExists;
    }

    private boolean isAuthPolicyAccountExistCheck() {

        return Boolean.parseBoolean(IdentityUtil.getProperty("AuthenticationPolicy.CheckAccountExist"));
    }

    private String buildAccountState(String state, String tenantDomain, UserStoreManager userStoreManager,
                                     String userName) throws AccountLockException {

        boolean isAccountStateClaimExist = AccountUtil.isAccountStateClaimExisting(tenantDomain);
        String newAccountstate = null;
        if (isAccountStateClaimExist) {
            if (isAccountDisabled(userStoreManager, userName)) {
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

    private String getAccountState(UserStoreManager userStoreManager, String tenantDomain, String userName)
            throws AccountLockException {

        String accountStateClaimValue = null;
        try {
            boolean isAccountStateClaimExist = AccountUtil.isAccountStateClaimExisting(tenantDomain);
            if (isAccountStateClaimExist) {
                Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                        AccountConstants.ACCOUNT_STATE_CLAIM_URI}, UserCoreConstants.DEFAULT_PROFILE);
                accountStateClaimValue = claimValues.get(AccountConstants.ACCOUNT_STATE_CLAIM_URI);
            }
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving account state claim value", e);
        }
        return accountStateClaimValue;
    }

    private boolean isAccountDisabled(UserStoreManager userStoreManager, String userName) throws AccountLockException {

        boolean accountDisabled = false;
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                    AccountConstants.ACCOUNT_DISABLED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            accountDisabled = Boolean.parseBoolean(claimValues.get(AccountConstants
                    .ACCOUNT_DISABLED_CLAIM));
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_DISABLED_CLAIM + " claim value", e);
        }
        return accountDisabled;
    }

    private void setUserClaim(String claimName, String claimValue, UserStoreManager userStoreManager,
                              String username, String tenantDomain) throws AccountLockException {

        HashMap<String, String> userClaims = new HashMap<>();
        userClaims.put(claimName, claimValue);
        setUserClaims(username, tenantDomain, userStoreManager, userClaims);
    }

    private String getClaimValue(String username, org.wso2.carbon.user.api.UserStoreManager userStoreManager,
                                 String claimURI) throws AccountLockException {

        try {
            Map<String, String> values = userStoreManager.getUserClaimValues(username, new String[]{claimURI},
                    UserCoreConstants.DEFAULT_PROFILE);
            return values.get(claimURI);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving claim: " + claimURI, e);
        }
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
     */
    private void auditAccountLock(String action, String target, String userStoreDomainName, boolean isAdminInitiated,
                                  String errorMsg, String result, Boolean isModifiedStatus) {

        JSONObject dataObject = new JSONObject();
        dataObject.put(AuditConstants.REMOTE_ADDRESS_KEY, MDC.get(AuditConstants.REMOTE_ADDRESS_QUERY_KEY));
        dataObject.put(AuditConstants.USER_AGENT_KEY, MDC.get(AuditConstants.USER_AGENT_QUERY_KEY));
        dataObject.put(AuditConstants.SERVICE_PROVIDER_KEY, MDC.get(AuditConstants.SERVICE_PROVIDER_QUERY_KEY));
        dataObject.put(AccountConstants.ADMIN_INITIATED, isAdminInitiated);
        dataObject.put(AuditConstants.USER_STORE_DOMAIN, userStoreDomainName);
        dataObject.put(AuditConstants.IS_MODIFIED_STATUS, isModifiedStatus);

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
                    "for user: %s in tenant: %s", username, tenantDomain), e);
        }
    }

    /**
     * Get user claim values for the given claims list.
     *
     * @param username         Username.
     * @param tenantDomain     Tenant domain.
     * @param userStoreManager UserStore Manager
     * @param claimsList       Claims list.
     * @return Claim values map.
     * @throws AccountLockException If an error occurred.
     */
    private Map<String, String> getUserClaimsFromUserStore(String username, String tenantDomain,
                                                           UserStoreManager userStoreManager, String[] claimsList)
            throws AccountLockException {

        try {
            return userStoreManager.getUserClaimValues(username, claimsList, UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            throw new AccountLockException(String.format("Error occurred while getting the user claims " +
                    "for user: %s in tenant: %s", username, tenantDomain), e);
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
}
