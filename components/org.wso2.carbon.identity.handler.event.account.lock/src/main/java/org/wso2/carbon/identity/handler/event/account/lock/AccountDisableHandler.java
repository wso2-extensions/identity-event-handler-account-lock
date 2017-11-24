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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class AccountDisableHandler extends AbstractEventHandler implements IdentityConnectorConfig {

    private static final Log log = LogFactory.getLog(AccountDisableHandler.class);

    private static ThreadLocal<String> disabledState = new ThreadLocal<>();

    private enum disabledStates {DISABLED_UNMODIFIED, DISABLED_MODIFIED, ENABLED_UNMODIFIED, ENABLED_MODIFIED}

    public String getName() {
        return "account.disable.handler";
    }

    @Override
    public String getFriendlyName() {
        return "Account Disabling";
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

    @Override
    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(AccountConstants.ACCOUNT_DISABLED_PROPERTY, "Enable Account Disabling");
        nameMapping.put(AccountConstants.ACCOUNT_DISABLED_NOTIFICATION_INTERNALLY_MANAGE, "Enable Notification Internally Management");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(AccountConstants.ACCOUNT_DISABLED_PROPERTY, "Enable account disable Feature");
        descriptionMapping.put(AccountConstants.ACCOUNT_DISABLED_NOTIFICATION_INTERNALLY_MANAGE, "Set false if the client application handles notification sending");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {
        List<String> properties = new ArrayList<>();
        properties.add(AccountConstants.ACCOUNT_DISABLED_PROPERTY);
        properties.add(AccountConstants.ACCOUNT_DISABLED_NOTIFICATION_INTERNALLY_MANAGE);

        return properties.toArray(new String[properties.size()]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {
        return configs.getModuleProperties();
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {
        return null;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        Map<String, Object> eventProperties = event.getEventProperties();
        String userName = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(IdentityEventConstants.EventProperty
                .USER_STORE_MANAGER);
        String userStoreDomainName = AccountUtil.getUserStoreDomainName(userStoreManager);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        // If the user store doesn't allow / support claim update  and read, skip this handler.
        if (!IdentityUtil.isSupportedByUserStore(userStoreManager, UserStoreConfigConstants.claimOperationsSupported)) {
            if (log.isDebugEnabled()) {
                log.debug("Claim operations are not supported by the user store. Hence returning");
            }
            return;
        }

        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, userStoreDomainName);
        boolean isAccountDisabledEnabled = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                .ACCOUNT_DISABLED_PROPERTY, tenantDomain));

        if (!isAccountDisabledEnabled) {
            if (log.isDebugEnabled()) {
                log.debug("Account disable feature is disabled for tenant :" + tenantDomain);
            }
            return;
        }

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
            handlePreAuthentication(event, userName, userStoreManager, userStoreDomainName, tenantDomain);
        } else if (IdentityEventConstants.Event.PRE_SET_USER_CLAIMS.equals(event.getEventName())) {
            handlePreSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain);
        } else if (IdentityEventConstants.Event.POST_SET_USER_CLAIMS.equals(event.getEventName())) {
            handlePostSetUserClaimValues(event, userName, userStoreManager, userStoreDomainName, tenantDomain);
        }
    }

    protected boolean handlePreAuthentication(Event event, String userName, UserStoreManager userStoreManager,
                                              String userStoreDomainName,
                                              String tenantDomain) throws AccountLockException {

        String accountDisabledClaim;
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                    AccountConstants.ACCOUNT_DISABLED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            accountDisabledClaim = claimValues.get(AccountConstants.ACCOUNT_DISABLED_CLAIM);

        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_DISABLED_CLAIM + " claim value", e);
        }
        if (Boolean.parseBoolean(accountDisabledClaim)) {
            String message;
            if (StringUtils.isNotBlank(userStoreDomainName)) {
                message = "Account is disabled for user " + userName + " in user store "
                        + userStoreDomainName + " in tenant " + tenantDomain + ". Cannot login until the " +
                        "account is enabled.";
            } else {
                message = "Account is disabled for user " + userName + " in tenant " + tenantDomain + ". Cannot" +
                        " login until the account is enabled.";
            }

            if (log.isDebugEnabled()) {
                log.debug(String.format("Authentication failed for user %s as the account is disabled", userName));
            }

            IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                    IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE);
            IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);

            throw new AccountLockException(IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE, message);
        }
        return true;
    }

    protected boolean handlePreSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                  String userStoreDomainName,
                                                  String tenantDomain) throws AccountLockException {


        if (disabledState.get() != null) {
            return true;
        }
        boolean existingAccountDisabledValue;
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userName, new String[]{
                    AccountConstants.ACCOUNT_DISABLED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            existingAccountDisabledValue = Boolean.parseBoolean(claimValues.get(AccountConstants
                    .ACCOUNT_DISABLED_CLAIM));
        } catch (UserStoreException e) {
            throw new AccountLockException("Error occurred while retrieving " + AccountConstants
                    .ACCOUNT_DISABLED_CLAIM + " claim value", e);
        }

        String newAccountDisableString = ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS")).get
                (AccountConstants.ACCOUNT_DISABLED_CLAIM);
        if (StringUtils.isNotBlank(newAccountDisableString)) {
            Boolean newAccountDisabledValue = Boolean.parseBoolean(
                    ((Map<String, String>) event.getEventProperties().get("USER_CLAIMS"))
                            .get(AccountConstants.ACCOUNT_DISABLED_CLAIM));
            if (existingAccountDisabledValue != newAccountDisabledValue) {
                if (existingAccountDisabledValue) {
                    disabledState.set(disabledStates.ENABLED_MODIFIED.toString());
                } else {
                    disabledState.set(disabledStates.DISABLED_MODIFIED.toString());
                    IdentityErrorMsgContext customErrorMessageContext = new IdentityErrorMsgContext(
                            IdentityCoreConstants.USER_ACCOUNT_DISABLED);
                    IdentityUtil.setIdentityErrorMsg(customErrorMessageContext);
                    IdentityUtil.threadLocalProperties.get().put(IdentityCoreConstants.USER_ACCOUNT_STATE,
                            IdentityCoreConstants.USER_ACCOUNT_DISABLED_ERROR_CODE);
                }
            } else {
                if (existingAccountDisabledValue) {
                    disabledState.set(disabledStates.DISABLED_UNMODIFIED.toString());
                } else {
                    disabledState.set(disabledStates.ENABLED_UNMODIFIED.toString());
                }
            }
        } else {
            if (existingAccountDisabledValue) {
                disabledState.set(disabledStates.DISABLED_UNMODIFIED.toString());
            } else {
                disabledState.set(disabledStates.ENABLED_UNMODIFIED.toString());
            }
        }
        return true;
    }

    protected boolean handlePostSetUserClaimValues(Event event, String userName, UserStoreManager userStoreManager,
                                                   String userStoreDomainName,
                                                   String tenantDomain) throws AccountLockException {

        try {

            boolean notificationInternallyManage = true;

            try {
                notificationInternallyManage = Boolean.parseBoolean(AccountUtil.getConnectorConfig(AccountConstants
                        .ACCOUNT_DISABLED_NOTIFICATION_INTERNALLY_MANAGE, tenantDomain));
            } catch (IdentityEventException e) {
                log.warn("Error while reading Notification internally manage property in account lock handler");
                if (log.isDebugEnabled()) {
                    log.debug("Error while reading Notification internally manage property in account lock handler", e);
                }
            }

            if (disabledStates.ENABLED_MODIFIED.toString().equals(disabledState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is enabled", userName));
                }

                if (notificationInternallyManage) {
                    triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                            AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_ENABLED);
                }
            } else if (disabledStates.DISABLED_MODIFIED.toString().equals(disabledState.get())) {

                if (log.isDebugEnabled()) {
                    log.debug(String.format("User %s is disabled", userName));
                }

                if (notificationInternallyManage) {
                    triggerNotification(event, userName, userStoreManager, userStoreDomainName, tenantDomain,
                            AccountConstants.EMAIL_TEMPLATE_TYPE_ACC_DISABLED);
                }
            }
        } finally {
            disabledState.remove();
        }
        return true;
    }

    protected void triggerNotification(Event event, String userName, UserStoreManager userStoreManager,
                                       String userStoreDomainName, String tenantDomain,
                                       String notificationEvent) throws AccountLockException {

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
}