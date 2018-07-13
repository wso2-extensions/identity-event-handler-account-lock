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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.identity.handler.event.account.lock.util.AccountUtil;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.List;
import java.util.ArrayList;

public class AccountLockHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    private static final Log log = LogFactory.getLog(AccountLockHandler.class);

    private static ThreadLocal<String> lockedState = new ThreadLocal<>();

    private enum lockedStates {LOCKED_MODIFIED, UNLOCKED_MODIFIED, LOCKED_UNMODIFIED, UNLOCKED_UNMODIFIED}

    public String getName() {
        return "account.lock.handler";
    }

    public String getFriendlyName() {
        return "Account Locking";
    }

    @Override
    public String getCategory() {
        return "Login Policies";
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
        nameMapping.put(AccountConstants.ACCOUNT_LOCKED_PROPERTY, "Account Lock Enabled");
        nameMapping.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Maximum Failed Login Attempts");
        nameMapping.put(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Account Unlock Time");
        nameMapping.put(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY, "Lock Timeout Increment Factor");
        nameMapping.put(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE, "Enable Notification Internally Management");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(AccountConstants.ACCOUNT_LOCKED_PROPERTY, "Enable account locking for failed logins");
        descriptionMapping.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Number of failed attempts allows without locking the account");
        descriptionMapping.put(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Account locked time span in minutes");
        descriptionMapping.put(AccountConstants.NOTIFICATION_INTERNALLY_MANAGE, "Set false if the client application handles notification sending");
        return descriptionMapping;
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 100;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        String userStoreDomainName = AccountUtil.getUserStoreDomainName(userStoreManager);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        Property[] identityProperties = null;
        Boolean accountLockedEnabled = false;
        String accountLockTime = "0";
        int maximumFailedAttempts = 0;
        double unlockTimeRatio = 1;
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
            handlePostSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                    identityProperties, maximumFailedAttempts, accountLockTime, unlockTimeRatio);
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

        if (isAccountLock(userName, userStoreManager)) {
            if (isAccountLockByPassForUser(userStoreManager, userName)) {
                if (log.isDebugEnabled()) {
                    String bypassMsg = String.format("Account locking is bypassed as lock bypass role: %s is " +
                            "assigned to the user %s", AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE, userName);
                    log.debug(bypassMsg);
                }
                return true;
            }

            //User account is locked. If the current time is not exceeded user unlock time, send a error message
            // saying user is locked, otherwise users can try to authenticate and unlock their account upon a
            // successful authentication.

            long unlockTime = getUnlockTime(userName, userStoreManager);

            if (System.currentTimeMillis() < unlockTime || unlockTime == 0) {

                String message;
                if (StringUtils.isNotBlank(userStoreDomainName)) {
                    message = "Account is locked for user " + userName + " in user store "
                            + userStoreDomainName + " in tenant " + tenantDomain + ". Cannot login until the " +
                            "account is unlocked.";
                } else {
                    message = "Account is locked for user " + userName + " in tenant " + tenantDomain + ". Cannot" +
                            " login until the account is unlocked.";
                }

                if (log.isDebugEnabled()) {
                    log.debug(message);
                }

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.USER_IS_LOCKED);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                throw new AccountLockException(UserCoreConstants.ErrorCode.USER_IS_LOCKED, message);
            }
        }
        return true;
    }

    protected boolean handlePostAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                               String userStoreDomainName, String tenantDomain,
                                               Property[] identityProperties, int maximumFailedAttempts,
                                               String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        Map<String, String> claimValues = null;
        int currentFailedAttempts = 0;
        try {
            claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                            AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                            AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM,
                            AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM,
                            AccountConstants.ACCOUNT_LOCKED_CLAIM}
                    , UserCoreConstants.DEFAULT_PROFILE);

            String currentFailedAttemptCount = claimValues.get(AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM);
            if (StringUtils.isNotBlank(currentFailedAttemptCount)) {
                currentFailedAttempts = Integer.parseInt(currentFailedAttemptCount);
            }
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving "
                    + AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM + " , "
                    + AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM + " and "
                    + AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, e);
        }

        if ((Boolean) event.getEventProperties().get(IdentityEventConstants.EventProperty.OPERATION_STATUS)) {
            //User is authenticated, Need to check the unlock time to verify whether the user is previously locked.

            long unlockTime = 0;
            String userClaimValue = claimValues.get(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM);
            String accountLockClaim = claimValues.get(AccountConstants.ACCOUNT_LOCKED_CLAIM);
            if (NumberUtils.isNumber(userClaimValue)) {
                unlockTime = Long.parseLong(userClaimValue);
            }
            if (isUserUnlock(userName, userStoreManager, currentFailedAttempts, unlockTime, accountLockClaim)) {
                Map<String, String> newClaims = new HashMap<>();
                newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
                newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                newClaims.put(AccountConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                newClaims.put(AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");

                try {
                    userStoreManager.setUserClaimValues(userName, newClaims, null);

                    if (log.isDebugEnabled()) {
                        log.debug(String.format("User %s is unlocked after exceeding the account locked time or " +
                                        "account lock bypassing is enabled", userName));
                    }
                } catch (UserStoreException e) {
                    throw new AccountLockException("Error occurred while storing "
                            + AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM + ", "
                            + AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM + ", "
                            + AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM + " and "
                            + AccountConstants.ACCOUNT_LOCKED_CLAIM, e);
                }
            }
        } else {
            // user authentication failed

            int failedLoginLockoutCountValue = 0;
            String loginAttemptCycles = claimValues.get(AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM);
            if (NumberUtils.isNumber(loginAttemptCycles)) {
                failedLoginLockoutCountValue = Integer.parseInt(loginAttemptCycles);
            }

            currentFailedAttempts += 1;
            Map<String, String> newClaims = new HashMap<>();
            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, currentFailedAttempts + "");

            if (isAccountLockByPassForUser(userStoreManager, userName)) {
                IdentityErrorMsgContext customErrorMessageContext =
                        new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL,
                                currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                if (log.isDebugEnabled()) {
                    String msg = String.format("Login attempt failed. Bypassing account locking for user %s", userName);
                    log.debug(msg);
                }
                return true;
            } else if (currentFailedAttempts >= maximumFailedAttempts) {
                //Current failed attempts exceeded maximum allowed attempts. So their user should be locked.

                newClaims.put(AccountConstants.ACCOUNT_LOCKED_CLAIM, "true");
                if (NumberUtils.isNumber(accountLockTime)) {
                    long unlockTimePropertyValue = Integer.parseInt(accountLockTime);
                    if (unlockTimePropertyValue != 0) {

                        if (log.isDebugEnabled()) {
                            log.debug("Set account unlock time for user:" + userName + " of tenant domain: " +
                                    tenantDomain + " userstore domain: " + userStoreDomainName + " adding account " +
                                    "unlock time out: " + unlockTimePropertyValue + ", account lock timeout increment" +
                                    " factor: " + unlockTimeRatio + " raised to the power of failed login attempt " +
                                    "cycles: " + failedLoginLockoutCountValue);
                        }

                        /**
                         * If account unlock time out is configured, calculates the account unlock time as below.
                         * account unlock time =
                         *      current system time + (account unlock time out configured + account lock time out
                         *      increment factor raised to the power of failed login attempt cycles)
                         */
                        unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000 * 60 * Math.pow
                                (unlockTimeRatio, failedLoginLockoutCountValue));
                        long unlockTime = System.currentTimeMillis() + unlockTimePropertyValue;
                        newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, unlockTime + "");
                    }
                }

                failedLoginLockoutCountValue = failedLoginLockoutCountValue + 1;
                newClaims.put(AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, failedLoginLockoutCountValue + "");
                newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");

                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants
                        .ErrorCode.USER_IS_LOCKED, currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.USER_ACCOUNT_STATE,
                        UserCoreConstants.ErrorCode.USER_IS_LOCKED);

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is locked since he/she exceeded the maximum allowed failed attempts", userName));
                }

            } else {
                IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(UserCoreConstants.ErrorCode.INVALID_CREDENTIAL,
                        currentFailedAttempts, maximumFailedAttempts);
                IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
            }
            try {
                userStoreManager.setUserClaimValues(userName, newClaims, null);
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while locking user account", e);
            } catch (NumberFormatException e) {
                throw new AccountLockException("Error occurred while parsing config values", e);
            }
        }
        return true;
    }

    /**
     * Check whether the account can be unlocked by checking whether account unlock time is exceeded or account bypass
     * role is attached
     * @param userName name of the logged in user
     * @param userStoreManager user store
     * @param currentFailedAttempts number of fail attempts
     * @param unlockTime time which account can be unlocked
     * @param accountLockClaim current lock claim value
     * @return whether the account can be unlocked
     * @throws AccountLockException
     */
    private boolean isUserUnlock(String userName, UserStoreManager userStoreManager, int currentFailedAttempts,
                                 long unlockTime, String accountLockClaim) throws AccountLockException {

        return (unlockTime != 0 && System.currentTimeMillis() >= unlockTime)
                || currentFailedAttempts > 0
                || ((Boolean.parseBoolean(accountLockClaim) && isAccountLockByPassForUser(userStoreManager, userName)));
    }

    protected boolean handlePreSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                  String userStoreDomainName, String tenantDomain,
                                                  Property[] identityProperties, int maximumFailedAttempts,
                                                  String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        if (lockedState.get() != null) {
            return true;
        }
        Boolean existingAccountLockedValue;
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                    AccountConstants.ACCOUNT_LOCKED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            existingAccountLockedValue = Boolean.valueOf(claimValues.get(AccountConstants.ACCOUNT_LOCKED_CLAIM));

        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_LOCKED_CLAIM + " claim value", e);
        }
        String newStateString = ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS")).get(AccountConstants.ACCOUNT_LOCKED_CLAIM);
        if (StringUtils.isNotBlank(newStateString)) {
            Boolean newAccountLockedValue = Boolean.parseBoolean(
                    ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS"))
                            .get(AccountConstants.ACCOUNT_LOCKED_CLAIM));
            if (existingAccountLockedValue != newAccountLockedValue) {
                if (existingAccountLockedValue) {
                    lockedState.set(lockedStates.UNLOCKED_MODIFIED.toString());
                } else {
                    lockedState.set(lockedStates.LOCKED_MODIFIED.toString());
                    IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.USER_ACCOUNT_STATE,
                            UserCoreConstants.ErrorCode.USER_IS_LOCKED);
                }
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
                                                   String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        try {
            boolean notificationInternallyManage = true;

            try {
                notificationInternallyManage = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                        .NOTIFICATION_INTERNALLY_MANAGE, tenantDomain));
            } catch (IdentityEventException e) {
                log.warn("Error while reading Notification internally manage property in account lock handler");
                if (log.isDebugEnabled()) {
                    log.debug("Error while reading Notification internally manage property in account lock handler", e);
                }
            }

            if (lockedStates.UNLOCKED_MODIFIED.toString().equals(lockedState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is unlocked", userName));
                }

                if (notificationInternallyManage) {
                    triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, identityProperties,
                            AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED);
                }
            } else if (lockedStates.LOCKED_MODIFIED.toString().equals(lockedState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is locked", userName));
                }

                if (notificationInternallyManage) {
                    triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, identityProperties,
                            AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED);
                }
            }
        } finally {
            lockedState.remove();
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
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
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
                    AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            String userClaimValue = values.get(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM);

            if (NumberUtils.isNumber(userClaimValue)) {
                unlockTime = Long.parseLong(userClaimValue);
            }
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_UNLOCK_TIME_CLAIM + " claim value", e);
        }
        return unlockTime;
    }

    /**
     *
     * @param userName Current username
     * @param userStoreManager User store
     * @return State whether current user is a privileged user
     * @throws AccountLockException
     */
    protected boolean isAccountLock(String userName, UserStoreManager userStoreManager) throws AccountLockException {

        String accountLockedClaim;
        try {
            Map<String, String> values = userStoreManager.getUserClaimValues(userName, new String[]{
                    AccountConstants.ACCOUNT_LOCKED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            accountLockedClaim = values.get(AccountConstants.ACCOUNT_LOCKED_CLAIM);

        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_LOCKED_CLAIM + " claim value", e);
        }
        return Boolean.parseBoolean(accountLockedClaim);
    }

    private boolean isUserExistsInDomain(UserStoreManager userStoreManager, String userName) throws AccountLockException {

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

    private boolean isAccountLockByPassForUser(UserStoreManager userStoreManager, String userName) throws AccountLockException {

        try {
            String[] roleList = userStoreManager.getRoleListOfUser(userName);
            if (!ArrayUtils.isEmpty(roleList)) {
                return ArrayUtils.contains(roleList, AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE);
            }
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while listing user role: " + userName, e);
        }
        return false;
    }
}
