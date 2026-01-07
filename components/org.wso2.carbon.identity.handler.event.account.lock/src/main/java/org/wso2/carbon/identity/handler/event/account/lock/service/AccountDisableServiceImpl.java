/*
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.handler.event.account.lock.service;

import org.osgi.annotation.bundle.Capability;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountDisableServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Map;

/**
 * Service implementation class of {@link AccountDisableService} that returns account disabled state.
 */
@Capability(
        namespace = "osgi.service",
        attribute = {
                "objectClass=org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService",
                "service.scope=singleton"
        }
)
public class AccountDisableServiceImpl implements AccountDisableService {

    @Override
    public boolean isAccountDisabled(String username, String tenantDomain, String userStoreDomain)
            throws AccountDisableServiceException {

        String domainAwareUsername = IdentityUtil.addDomainToName(username, userStoreDomain);
        UserStoreManager userStoreManager = getUserStoreManager(tenantDomain);
        // Account is considered to be disabled, if the account disabled claim is set to 'true'.
        return getAccountDisabledClaimValue(domainAwareUsername, userStoreManager);
    }

    private UserStoreManager getUserStoreManager(String tenantDomain) throws AccountDisableServiceException {

        int tenantId;
        try {
            tenantId = AccountServiceDataHolder.getInstance().getRealmService().getTenantManager()
                    .getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            throw new AccountDisableServiceException(
                    "Could not retrieve tenant id from tenant domain: " + tenantDomain, e);
        }
        if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
            throw new AccountDisableServiceException("Invalid tenant domain: " + tenantDomain);
        }

        UserRealm userRealm;
        try {
            userRealm = AccountServiceDataHolder.getInstance().getRealmService().getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new AccountDisableServiceException(
                    "Could not retrieve user realm for tenant domain: " + tenantDomain, e);
        }
        try {
            return userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AccountDisableServiceException(
                    "Could not retrieve user store for tenant domain: " + tenantDomain, e);
        }
    }

    private boolean getAccountDisabledClaimValue(String username, UserStoreManager userStoreManager)
            throws AccountDisableServiceException {

        String accountDisabledClaimValue;
        try {
            Map<String, String> values = userStoreManager.getUserClaimValues(username,
                    new String[]{AccountConstants.ACCOUNT_DISABLED_CLAIM}, UserCoreConstants.DEFAULT_PROFILE);
            accountDisabledClaimValue = values.get(AccountConstants.ACCOUNT_DISABLED_CLAIM);
        } catch (UserStoreException e) {
            throw new AccountDisableServiceException(
                    "Error occurred while retrieving claim: " + AccountConstants.ACCOUNT_DISABLED_CLAIM, e);
        }

        return Boolean.parseBoolean(accountDisabledClaimValue);
    }
}
