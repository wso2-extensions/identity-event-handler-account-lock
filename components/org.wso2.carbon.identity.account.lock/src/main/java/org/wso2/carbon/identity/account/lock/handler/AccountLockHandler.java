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

package org.wso2.carbon.identity.account.lock.handler;

import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.account.lock.constants.AccountLockConstants;
import org.wso2.carbon.identity.account.lock.internal.IdentityAccountLockServiceDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityGovernanceConnector;
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

    private enum lockedStates {LOCKED, UNLOCKED, NO_CHANGE}

    public String getName() {
        return "accountLock";
    }

    public String getFriendlyName() {
        return "Account Locking";
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(AccountLockConstants.ACCOUNT_LOCKED_PROPERTY, "Account Lock Enabled");
        nameMapping.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY, "Maximum Failed Login Attempts");
        nameMapping.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_PROPERTY, "Account Unlock Time");
        nameMapping.put(AccountLockConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY, "Time Ratio for Incorrect Login Attempts");
        return nameMapping;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);
        Property[] identityProperties = null;
        Boolean accountLockedEnabled = false;
        String accountLockTime = "0";
        String unlockTimeRatio = "1" ;
        int maximumFailedAttempts = 0;
        try {
            identityProperties = IdentityAccountLockServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while retrieving account lock handler properties.", e);
        }
        for (Property identityProperty : identityProperties) {
            if (AccountLockConstants.ACCOUNT_LOCKED_PROPERTY.equals(identityProperty.getName())) {
                accountLockedEnabled = Boolean.parseBoolean(identityProperty.getValue());
            } else if (AccountLockConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY.equals(identityProperty.getName())) {
                maximumFailedAttempts = Integer.parseInt(identityProperty.getValue());
            } else if (AccountLockConstants.ACCOUNT_UNLOCK_TIME_PROPERTY.equals(identityProperty.getName())) {
                accountLockTime = identityProperty.getValue();
            } else if (AccountLockConstants.LOGIN_FAIL_TIMEOUT_RATIO_PROPERTY.equals(identityProperty.getName())) {
                unlockTimeRatio = identityProperty.getValue();
            }
        }
        IdentityUtil.clearIdentityErrorMsg();
        if (!accountLockedEnabled) {
            return;
        }
        String domainName = userStoreManager.getRealmConfiguration().getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, domainName);
        boolean isUserExistInCurrentDomain;
        try {
            isUserExistInCurrentDomain = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error in accessing user store");
        }

        if (IdentityEventConstants.Event.PRE_AUTHENTICATION.equals(event.getEventName())) {
            if (!isUserExistInCurrentDomain) {
                return;
            } else {
                try {
                    if (Boolean.parseBoolean(userStoreManager.getUserClaimValue(userName,
                            AccountLockConstants.ACCOUNT_LOCKED_CLAIM, null))) {
                        long unlockTime = Long.parseLong(userStoreManager.getUserClaimValue(userName,
                                AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, null));
                        if ((unlockTime != 0) && (System.currentTimeMillis() >= unlockTime)) {

                            Map<String, String> newClaims = new HashMap<>();
                            newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                            newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                            newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
                            userStoreManager.setUserClaimValues(userName, newClaims, null);
                        } else {
                            String errorMsg = "User account is locked for user : " + userName
                                    + ". cannot login until the account is unlocked ";
                            throw new IdentityEventException(UserCoreConstants.ErrorCode.USER_IS_LOCKED + " "
                                    + errorMsg);
                        }
                    }
                } catch (UserStoreException e) {
                    throw new IdentityEventException("Error while retrieving account lock claim value", e);
                }
            }
        } else if (IdentityEventConstants.Event.POST_AUTHENTICATION.equals(event.getEventName())) {
            if ((Boolean)eventProperties.get(IdentityEventConstants.EventProperty.OPERATION_STATUS)) {
                Map<String, String> newClaims = new HashMap<>();
                newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
                newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                newClaims.put(AccountLockConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");
                newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                try {
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new IdentityEventException("Error while setting up user identity claims.", e);
                }
            } else {
                try {
                    int failedLoginLockoutCountValue = 1 ;
                    String failedLoginLockoutCount = userStoreManager.getUserClaimValue(userName,
                                                                                        AccountLockConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, null);
                    if (NumberUtils.isNumber(failedLoginLockoutCount)) {
                        failedLoginLockoutCountValue = Integer.parseInt(failedLoginLockoutCount);
                    }
                    String currentFailedAttempts = userStoreManager.getUserClaimValue(userName,
                            AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, null);
                    if (currentFailedAttempts == null) {
                        currentFailedAttempts = "0";
                    }
                    int numberOffailedAttermpts = Integer.parseInt(currentFailedAttempts) + 1;
                    Map<String, String> newClaims = new HashMap<>();
                    newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, numberOffailedAttermpts + "");
                    if (numberOffailedAttermpts >= maximumFailedAttempts) {
                        newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, "true");

                        long unlockTimePropertyValue = 1 ;
                        if (NumberUtils.isNumber(accountLockTime)) {
                            unlockTimePropertyValue = Integer.parseInt(accountLockTime);
                        }
                        failedLoginLockoutCountValue = failedLoginLockoutCountValue + 1 ;
                        int unlockTimeRatioValue = 1 ;
                        if(NumberUtils.isNumber(unlockTimeRatio)){
                            int tmpUnlockTimeRatioValue = Integer.parseInt(unlockTimeRatio);
                            if(tmpUnlockTimeRatioValue > 0){
                                unlockTimeRatioValue = tmpUnlockTimeRatioValue;
                            }
                        }
                        unlockTimePropertyValue = (long) (unlockTimePropertyValue * (1000 * unlockTimeRatioValue * 60)  * failedLoginLockoutCountValue);
                        long unlockTime = System.currentTimeMillis() + Long.parseLong(unlockTimePropertyValue + "") ;

                        newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, unlockTime + "");
                        newClaims.put(AccountLockConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, ++failedLoginLockoutCountValue + "");
                    }
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new IdentityEventException("Error while locking account.", e);
                }
            }
        } else if (IdentityEventConstants.Event.PRE_SET_USER_CLAIMS.equals(event.getEventName())) {
            if (lockedState.get() != null) {
                return;
            }
            try {
                boolean currentState = Boolean.parseBoolean(userStoreManager.getUserClaimValue(userName,
                                                                                               AccountLockConstants.ACCOUNT_LOCKED_CLAIM, null));
                boolean newState = Boolean.parseBoolean(((Map<String, String>)((Map<String, Object>) event
                        .getEventProperties()).get("USER_CLAIMS")).get(AccountLockConstants.ACCOUNT_LOCKED_CLAIM));
                if (currentState != newState){
                    if (currentState) {
                        lockedState.set(lockedStates.UNLOCKED.toString());
                    } else {
                        lockedState.set(lockedStates.LOCKED.toString());
                    }
                } else {
                    lockedState.set(lockedStates.NO_CHANGE.toString());
                }
            } catch (UserStoreException e) {
                throw new IdentityEventException("Error while retrieving user claims.", e);
            }

        } else if (IdentityEventConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName())) {
            if (lockedStates.UNLOCKED.toString().equals(lockedState.get())) {
                triggerNotification(userName, AccountLockConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED);
            } else if (lockedStates.LOCKED.toString().equals(lockedState.get())) {
                triggerNotification(userName, AccountLockConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED);
            }
            lockedState.remove();
        }
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {
        super.init(configuration);
        IdentityAccountLockServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityGovernanceConnector.class.getName(), this, null);
    }

    public String[] getPropertyNames(){
        String[] arr = this.configs.getModuleProperties().keySet().toArray(new String[this.properties.keySet().size()]);
        return arr;
    }

    public Properties getDefaultPropertyValues (String tenantDomain) throws IdentityGovernanceException{
       return configs.getModuleProperties();
    }

    public Map<String, String> getDefaultPropertyValues (String[] propertyNames, String tenantDomain) throws IdentityGovernanceException{
        return null;
    }

    private void triggerNotification (String userName, String type) throws IdentityEventException {

        String eventName = IdentityEventConstants.Event.TRIGGER_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, userName);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getTenantDomain());
        properties.put("TEMPLATE_TYPE", type);
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            IdentityAccountLockServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "Error occurred while calling triggerNotification, detail : " + e.getMessage() ;
            log.error(errorMsg);
            //We are not throwing any exception from here, because this event notification should not break the main flow.
        }

    }

}
