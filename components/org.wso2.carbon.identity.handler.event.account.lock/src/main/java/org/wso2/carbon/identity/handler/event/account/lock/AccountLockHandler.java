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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityGovernanceConnector;
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

public class AccountLockHandler extends AbstractEventHandler implements IdentityGovernanceConnector {

    private static final Log log = LogFactory.getLog(AccountLockHandler.class);

    private static ThreadLocal<String> lockedState = new ThreadLocal<>();
    private enum lockedStates {LOCKED_MODIFIED, UNLOCKED_MODIFIED, LOCKED_UNMODIFIED, UNLOCKED_UNMODIFIED}

    public String getName() {
        return "account.lock.handler";
    }

    public String getFriendlyName() {
        return "Account Locking Connector";
    }

    @Override
    public void init(InitConfig initConfig) {
        super.init(initConfig);
        AccountServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityGovernanceConnector.class.getName(), this, null);
    }

    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(AccountConstants.ACCOUNT_LOCKED_PROPERTY, "Account Lock Enabled");
        nameMapping.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Maximum Failed Login Attempts");
        nameMapping.put(AccountConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Account Unlock Time");
        nameMapping.put(AccountConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY, "Lock Timeout Increment Factor");
        return nameMapping;
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 100 ;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        IdentityUtil.clearIdentityErrorMsg();

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
                if(NumberUtils.isNumber(value)) {
                    if (Integer.parseInt(value) > 0) {
                        unlockTimeRatio = Integer.parseInt(value);
                    }
                }
            }
        }

        if (!accountLockedEnabled) {
            return;
        }

        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, userStoreDomainName);
        boolean userExists;
        try {
            userExists = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error in accessing user store");
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

        String accountLockedClaim = null;
        try {
            accountLockedClaim = userStoreManager.getUserClaimValue(userName,
                                                                    AccountConstants.ACCOUNT_LOCKED_CLAIM, null);
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_LOCKED_CLAIM + " claim value");
        }
        if (Boolean.parseBoolean(accountLockedClaim)) {
            long unlockTime = 0;
            try {
                String userClaimValue = userStoreManager.getUserClaimValue(userName,
                                                                  AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, null);
                if(NumberUtils.isNumber(userClaimValue)){
                    unlockTime = Long.parseLong(userClaimValue);
                }
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                        .ACCOUNT_UNLOCK_TIME_CLAIM + " claim value");
            }
            if (unlockTime != 0 && System.currentTimeMillis() >= unlockTime) {
                Map<String, String> newClaims = new HashMap<>();
                newClaims.put(AccountConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
                try {
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new AccountLockException("Error occurred while storing " + AccountConstants
                            .ACCOUNT_LOCKED_CLAIM + " and " + AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM +
                                                   "claim values");
                }
            } else {
                String message = null;
                if (StringUtils.isNotBlank(userStoreDomainName)) {
                    message = "Account is locked for user " + userName + " in user store "
                              + userStoreDomainName + " in tenant " + tenantDomain + ". Cannot login until the " +
                              "account is unlocked.";
                } else {
                    message = "Account is locked for user " + userName + " in tenant " + tenantDomain + ". Cannot" +
                              " login until the account is unlocked.";
                }
                throw new AccountLockException(UserCoreConstants.ErrorCode.USER_IS_LOCKED + " " + message);
            }
        }
        return true;
    }

    protected boolean handlePostAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                               String userStoreDomainName, String tenantDomain,
                                               Property[] identityProperties, int maximumFailedAttempts,
                                               String accountLockTime, double unlockTimeRatio)
            throws AccountLockException {

        if ((Boolean) event.getEventProperties().get(IdentityEventConstants.EventProperty.OPERATION_STATUS)) {
            Map<String, String> newClaims = new HashMap<>();
            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
            newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
            newClaims.put(AccountConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
            newClaims.put(AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");
            try {
                //TODO need to support readOnly user stores too. IDENTITY-4754
                if (!userStoreManager.isReadOnly()) {
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                }
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while storing " + AccountConstants
                        .FAILED_LOGIN_ATTEMPTS_CLAIM + ", " + AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM + " and " +
                                               "" + AccountConstants.ACCOUNT_LOCKED_CLAIM, e);
            }
        } else {
            int failedLoginLockoutCountValue = 0;
            int currentFailedAttempts;
            try {
                String loginAttemptCycles = userStoreManager.getUserClaimValue(userName,
                                                                                    AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM,
                                                                                    null);
                if (NumberUtils.isNumber(loginAttemptCycles)) {
                    failedLoginLockoutCountValue = Integer.parseInt(loginAttemptCycles);
                }
                currentFailedAttempts = Integer.parseInt(userStoreManager.getUserClaimValue(userName,
                                                                                            AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM,
                                                                                            null));
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                        .FAILED_LOGIN_ATTEMPTS_CLAIM + " claim value");
            }
            currentFailedAttempts += 1;
            Map<String, String> newClaims = new HashMap<>();
            newClaims.put(AccountConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, currentFailedAttempts + "");
            if (currentFailedAttempts >= maximumFailedAttempts) {
                newClaims.put(AccountConstants.ACCOUNT_LOCKED_CLAIM, "true");
                long unlockTimePropertyValue = 1 ;
                if (NumberUtils.isNumber(accountLockTime)) {
                    unlockTimePropertyValue = Integer.parseInt(accountLockTime);
                }
                failedLoginLockoutCountValue = failedLoginLockoutCountValue + 1 ;
                unlockTimePropertyValue = (long) (unlockTimePropertyValue * 1000  * 60  * Math.pow(unlockTimeRatio,
                                                                                                   failedLoginLockoutCountValue));
                long unlockTime = System.currentTimeMillis() + Long.parseLong(unlockTimePropertyValue + "") ;

                newClaims.put(AccountConstants.ACCOUNT_UNLOCK_TIME_CLAIM, unlockTime + "");
                newClaims.put(AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, failedLoginLockoutCountValue + "");
            }
            try {
                userStoreManager.setUserClaimValues(userName, newClaims, null);
            } catch (UserStoreException e) {
                throw new AccountLockException("Error occurred while locking user account");
            } catch (NumberFormatException e) {
                throw new AccountLockException("Error occurred while parsing config values", e);
            }
        }
        return true;
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
            existingAccountLockedValue = Boolean.parseBoolean(userStoreManager.getUserClaimValue(userName,
                                                                                                 AccountConstants.ACCOUNT_LOCKED_CLAIM, null));
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_LOCKED_CLAIM + " claim value");
        }
        Boolean newAccountLockedValue = Boolean.parseBoolean(
                ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS"))
                        .get(AccountConstants.ACCOUNT_LOCKED_CLAIM));
        if (existingAccountLockedValue != newAccountLockedValue) {
            if (existingAccountLockedValue) {
                lockedState.set(lockedStates.UNLOCKED_MODIFIED.toString());
            } else {
                lockedState.set(lockedStates.LOCKED_MODIFIED.toString());
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
            if (lockedStates.UNLOCKED_MODIFIED.toString().equals(lockedState.get())) {
                triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, identityProperties,
                                    AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED);
            } else if (lockedStates.LOCKED_MODIFIED.toString().equals(lockedState.get())) {
                triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain, identityProperties,
                                    AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED);
            }
        } finally {
            lockedState.remove();
        }
        return true;
    }

    public String[] getPropertyNames() {

        String[] arr = this.configs.getModuleProperties().keySet().toArray(new String[this.properties.keySet().size()]);
        return arr;
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
                                       Property[] identityProperties, String notificationEvent) {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_MANAGER, userStoreManager);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, userStoreDomainName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, tenantDomain);
        properties.put("TEMPLATE_TYPE", notificationEvent);
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AccountServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage() ;
            log.error(errorMsg);
            //We are not throwing any exception from here, because this event notification should not break the main flow.
        }
    }

}