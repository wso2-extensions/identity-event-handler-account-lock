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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.email.mgt.exceptions.I18nEmailMgtException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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
import org.wso2.carbon.user.core.UserStoreConfigConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

public class AccountUtil {

    private static final Log log = LogFactory.getLog(AccountUtil.class);

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
     * @param eventName                 Event name.
     * @param properties                Event properties.
     * @throws AccountLockException     Account Lock Exception.
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
     * Clones the given map.
     *
     * @param map          Map.
     * @return             Cloned Map.
     */
    public static Map<String, Object> cloneMap(Map<String, Object> map) {

        if (MapUtils.isEmpty(map)) {
            return null;
        }
        Map<String, Object> clonedMap = new HashMap<String, Object>();
        clonedMap.putAll(map);
        return clonedMap;
    }

    /**
     * To create an audit message based on provided parameters.
     *
     * @param action     The action.
     * @param target     The target affected by this activity.
     * @param dataObject The information passed along with the request.
     * @param result     The result value.
     */
     public static void createAuditMessage(String action, String target, JSONObject dataObject, String result) {

        String loggedInUser = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        if (StringUtils.isBlank(loggedInUser)) {
            if (log.isDebugEnabled()) {
                log.debug("There is no logged in user. Therefore using the default registry system username when " +
                        "creating the audit message.");
            }
            loggedInUser = AuditConstants.REGISTRY_SYSTEM_USERNAME;
        }
        CarbonConstants.AUDIT_LOG.info(String.format(AuditConstants.AUDIT_MESSAGE, getInitiator(loggedInUser), action,
                getTarget(target), dataObject, result));
    }

    /**
     * Check if the given user has a role capable of bypassing the account lock.
     *
     * @param userStoreManager Userstore manager
     * @param userName Username of the user.
     * @return Returns ture if the user can bypass account lock.
     * @throws AccountLockException
     */
    public static boolean isAccountLockByPassForUser(UserStoreManager userStoreManager,
                                                      String userName) throws AccountLockException {

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

    /**
     * Check if the account lock by pass is enabled for the userstore.
     *
     * @param userStoreManager Userstore Manager.
     * @return true if account lock by pass is enabled for userstore.
     */
    public static boolean isAccountLockBypassForUserStore(org.wso2.carbon.user.core.UserStoreManager userStoreManager) {

        String isAccountLockByPassEnabled = userStoreManager.getRealmConfiguration().getUserStoreProperty(
                UserStoreConfigConstants.BYPASS_ACCOUNT_LOCK);
        return Boolean.parseBoolean(isAccountLockByPassEnabled);
    }

    /**
     * Returns initiator for audit logs based on log masking config.
     *
     * @param loggedInUser  Logged in user.
     * @return initiator. Returns userId if log masking is enabled, if userId cannot be resolved then returns the masked
     * username.
     * */
    private static String getInitiator(String loggedInUser) {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String initiator = null;

        if (LoggerUtils.isLogMaskingEnable) {
            if (StringUtils.isNotBlank(tenantDomain) && StringUtils.isNotBlank(loggedInUser)) {
                initiator = IdentityUtil.getInitiatorId(loggedInUser, tenantDomain);
            } if (StringUtils.isBlank(initiator)) {
                initiator = LoggerUtils.getMaskedContent(loggedInUser);
            }
        } else {
            initiator = UserCoreUtil.addTenantDomainToEntry(loggedInUser, tenantDomain);
        }
        return initiator;
    }

    /** Retruns the target for audit log based on log masking config.
     *
     * @param target Target.
     * @return target. Returns masked value if log masking is enabled.
     */
    private static String getTarget(String target) {

        if (LoggerUtils.isLogMaskingEnable) {
            return LoggerUtils.getMaskedContent(target);
        }
        return target;
    }
}
