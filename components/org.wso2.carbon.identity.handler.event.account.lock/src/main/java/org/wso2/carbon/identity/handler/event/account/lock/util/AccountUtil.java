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

package org.wso2.carbon.identity.handler.event.account.lock.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.AuditConstants;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockException;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockRuntimeException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.email.mgt.exceptions.I18nEmailMgtException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

public class AccountUtil {

    private static final Log log = LogFactory.getLog(AccountUtil.class);
    private static final Log AUDIT_LOG = LogFactory.getLog("AUDIT_LOG");

    public static String getUserStoreDomainName(UserStoreManager userStoreManager) {
        String domainNameProperty = null;
        if(userStoreManager instanceof org.wso2.carbon.user.core.UserStoreManager) {
            domainNameProperty = ((org.wso2.carbon.user.core.UserStoreManager)
                                          userStoreManager).getRealmConfiguration()
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            if(StringUtils.isBlank(domainNameProperty)) {
                domainNameProperty = IdentityUtil.getPrimaryDomainName();
            }
        }
        return domainNameProperty;
    }

    public static String getTenantDomain(UserStoreManager userStoreManager) {
        try {
            return IdentityTenantUtil.getTenantDomain(userStoreManager.getTenantId());
        } catch (UserStoreException e) {
            throw AccountLockRuntimeException.error(e.getMessage(), e);
        }
    }

    public static String getConnectorConfig(String key, String tenantDomain) throws IdentityEventException {
        try {
            Property[] connectorConfigs;
            IdentityGovernanceService identityGovernanceService = AccountServiceDataHolder.getInstance()
                    .getIdentityGovernanceService();
            if (identityGovernanceService != null) {
                connectorConfigs = identityGovernanceService.getConfiguration(new String[]{key}, tenantDomain);
                if (connectorConfigs != null && connectorConfigs.length > 0) {
                    return connectorConfigs[0].getValue();
                }
            }
            return null;
        } catch (IdentityGovernanceException e) {
            throw new IdentityEventException("Error while getting connector configurations for property :" + key, e);
        }
    }

    public static boolean isAccountStateClaimExisting(String tenantDomain) throws AccountLockException {

        UserRealm userRealm = null;
        ClaimManager claimManager = null;

        RealmService realmService = AccountServiceDataHolder.getInstance().getRealmService();
        if (realmService != null) {
            //get tenant's user realm
            try {
                int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                userRealm = realmService.getTenantUserRealm(tenantId);

            } catch (UserStoreException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retriving user realm in AccountUtil", e);
                }
                throw new AccountLockException("Error while retriving user realm in AccountUtil");
            }
        }
        if (userRealm != null) {
            //get claim manager for manipulating attributes
            try {
                claimManager = (ClaimManager) userRealm.getClaimManager();
            } catch (UserStoreException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retriving claim manager in AccountUtil", e);
                }
                throw new AccountLockException("Error while retriving claim manager in AccountUtil");
            }
        }

        boolean isExist = false;
        try {
            Claim claim = claimManager.getClaim(AccountConstants.ACCOUNT_STATE_CLAIM_URI);
            if (claim != null) {
                isExist = true;
            }
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while checking accountState claim  from ClaimManager in AccountUtil", e);
            }
            throw new AccountLockException("Error while checking accountState claim  from ClaimManager");
        }
        return isExist;
    }

    /**
     * This is used to check the existence of a email template.
     *
     * @param templateType Template type display name.
     * @param tenantDomain Tenant domain.
     * @return Returns true if email template exists.
     * @throws AccountLockException Account Lock Exception.
     */
    public static boolean isTemplateExists(String templateType, String tenantDomain) throws AccountLockException {

        try {
            return AccountServiceDataHolder.getInstance().getEmailTemplateManager()
                    .isEmailTemplateTypeExists(templateType, tenantDomain);
        } catch (I18nEmailMgtException e) {
            throw new AccountLockException(
                    "Error occurred while checking email template type: " + templateType + " existence in the "
                            + "tenantDomain: " + tenantDomain, e);
        }
    }

    /**
     * Publishes an event.
     *
     * @param eventName                 Event name
     * @param properties                Event properties
     * @throws AccountLockException     if event sent failed
     */
    public static void publishEvent(String eventName, Map<String, Object> properties) throws AccountLockException {

        Event identityMgtEvent = new Event(eventName, properties);
        try {
            AccountServiceDataHolder.getInstance().getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            String errorMsg = "Error occurred while triggering the event : " + identityMgtEvent.getEventName();
            throw new AccountLockException(errorMsg, e);
        }
    }

    /**
     * Prepare and log the audit message.
     *
     * @param action                Activity
     * @param target                Target user affected by this activity
     * @param userStoreDomainName   User store domain of the user
     * @param isAdminInitiated      Is initiated by admin
     * @param errorMsg              Error message if any
     * @param result                Result of the activity
     */
    public static void printAuditLog(String action, String target, String userStoreDomainName,
                                                     Boolean isAdminInitiated, String errorMsg, String result) {

        JSONObject dataObject = new JSONObject();
        dataObject.put(AuditConstants.REMOTE_ADDRESS_KEY, MDC.get(AuditConstants.REMOTE_ADDRESS_QUERY_KEY));
        dataObject.put(AuditConstants.USER_AGENT_KEY, MDC.get(AuditConstants.USER_AGENT_QUERY_KEY));
        dataObject.put(AuditConstants.SERVICE_PROVIDER_KEY, MDC.get(AuditConstants.SERVICE_PROVIDER_QUERY_KEY));
        dataObject.put(AuditConstants.USER_STORE_DOMAIN, userStoreDomainName);

        if (isAdminInitiated != null) {
            dataObject.put(AccountConstants.ADMIN_INITIATED, isAdminInitiated);
        }

        if (AuditConstants.AUDIT_FAILED.equals(result)) {
            dataObject.put(AuditConstants.ERROR_MESSAGE_KEY, errorMsg);
        }

        String loggedInUser = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        if (StringUtils.isBlank(loggedInUser)) {
            loggedInUser = AuditConstants.REGISTRY_SYSTEM_USERNAME;
        }
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        loggedInUser = UserCoreUtil.addTenantDomainToEntry(loggedInUser, tenantDomain);
        AUDIT_LOG.info(String.format(AuditConstants.AUDIT_MESSAGE, loggedInUser, action, target, dataObject, result));
    }

}
