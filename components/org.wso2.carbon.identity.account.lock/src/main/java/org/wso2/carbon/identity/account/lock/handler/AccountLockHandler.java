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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.account.lock.constants.AccountLockConstants;
import org.wso2.carbon.identity.account.lock.internal.IdentityAccountLockServiceDataHolder;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.EventMgtConstants;
import org.wso2.carbon.identity.event.EventMgtException;
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
    public boolean handleEvent(Event event) throws EventMgtException {
        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(EventMgtConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(EventMgtConstants.EventProperty.USER_STORE_MANAGER);
        String tenantDomain = (String) eventProperties.get(EventMgtConstants.EventProperty.TENANT_DOMAIN);
        Map<String, String> identityProperties = null;
        try {
            identityProperties = IdentityAccountLockServiceDataHolder.getInstance()
                    .getIdentityGovernanceService().getConfiguration(getPropertyNames(), tenantDomain);
        } catch (IdentityGovernanceException e) {
            throw new EventMgtException("Error while retrieving account lock handler properties.", e);
        }
        IdentityUtil.clearIdentityErrorMsg();
        if (!Boolean.parseBoolean(identityProperties.get(AccountLockConstants.ACCOUNT_LOCKED_PROPERTY))) {
            return true;
        }
        String domainName = userStoreManager.getRealmConfiguration().getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, domainName);
        boolean isUserExistInCurrentDomain;
        try {
            isUserExistInCurrentDomain = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new EventMgtException("Error in accessing user store");
        }

        if (EventMgtConstants.Event.PRE_AUTHENTICATION.equals(event.getEventName())) {
            if (!isUserExistInCurrentDomain) {
                return true;
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
                            userStoreManager.setUserClaimValues(userName, newClaims, null);
                        } else {
                            String errorMsg = "User account is locked for user : " + userName
                                    + ". cannot login until the account is unlocked ";
                            throw new EventMgtException(UserCoreConstants.ErrorCode.USER_IS_LOCKED + " "
                                    + errorMsg);
                        }
                    }
                } catch (UserStoreException e) {
                    throw new EventMgtException("Error while retrieving account lock claim value", e);
                }
            }
        } else if (EventMgtConstants.Event.POST_AUTHENTICATION.equals(event.getEventName())) {
            if ((Boolean)eventProperties.get(EventMgtConstants.EventProperty.OPERATION_STATUS)) {
                Map<String, String> newClaims = new HashMap<>();
                newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
                newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                try {
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new EventMgtException("Error while setting up user identity claims.", e);
                }
            } else {
                try {
                    String currentFailedAttempts = userStoreManager.getUserClaimValue(userName,
                            AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, null);
                    if (currentFailedAttempts == null) {
                        currentFailedAttempts = "0";
                    }
                    int numberOffailedAttermpts = Integer.parseInt(currentFailedAttempts) + 1;
                    Map<String, String> newClaims = new HashMap<>();
                    newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, numberOffailedAttermpts + "");
                    if (numberOffailedAttermpts >= Integer.parseInt(identityProperties.get
                            (AccountLockConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY))) {
                        newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, "true");
                        String unlockTimeProperty = identityProperties.get(AccountLockConstants
                                .ACCOUNT_UNLOCK_TIME_PROPERTY);
                        if (!"0".equals(unlockTimeProperty) && unlockTimeProperty != null) {
                            long unlockTime = System.currentTimeMillis() + Integer.parseInt(unlockTimeProperty) * 60 * 1000L;
                            newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, unlockTime + "");
                        }
                    }
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new EventMgtException("Error while locking account.", e);
                }
            }
        } else if (EventMgtConstants.Event.PRE_SET_USER_CLAIMS.equals(event.getEventName())) {
            if (lockedState.get() != null) {
                return true;
            }
            try {
                Boolean currentState = Boolean.parseBoolean(userStoreManager.getUserClaimValue(userName,
                        AccountLockConstants.ACCOUNT_LOCKED_CLAIM, null));
                Boolean newState = Boolean.parseBoolean(((Map<String, String>)((Map<String, Object>) event
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
                e.printStackTrace();
            }

        } else if (EventMgtConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName())) {
            if (lockedStates.UNLOCKED.toString().equals(lockedState.get())) {
                triggerNotification(userName, AccountLockConstants.EMAIL_TEMPLATE_TYPE_ACC_UNLOCKED);
            } else if (lockedStates.LOCKED.toString().equals(lockedState.get())) {
                triggerNotification(userName, AccountLockConstants.EMAIL_TEMPLATE_TYPE_ACC_LOCKED);
            }
            lockedState.remove();
        }
        return true;
    }

    @Override
    public void init(InitConfig configuration) throws IdentityRuntimeException {
        super.init(configuration);
        IdentityAccountLockServiceDataHolder.getInstance().getBundleContext().registerService
                (IdentityGovernanceConnector.class.getName(), this, null);
    }

    public String[] getPropertyNames(){
        String[] arr = this.properties.keySet().toArray(new String[this.properties.keySet().size()]);
        return arr;
    }

    public Properties getDefaultPropertyValues (String tenantDomain) throws IdentityGovernanceException{
       return properties;
    }

    public Map<String, String> getDefaultPropertyValues (String[] propertyNames, String tenantDomain) throws IdentityGovernanceException{
        return null;
    }

    private void triggerNotification (String userName, String type) throws EventMgtException {

        String eventName = EventMgtConstants.Event.TRIGGER_NOTIFICATION;

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(EventMgtConstants.EventProperty.USER_NAME, userName);
        properties.put(EventMgtConstants.EventProperty.TENANT_DOMAIN, PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getTenantDomain());
        properties.put("TEMPLATE_TYPE", type);
        Event identityMgtEvent = new Event(eventName, properties);
        IdentityAccountLockServiceDataHolder.getInstance().getEventMgtService().handleEvent(identityMgtEvent);

    }

}
