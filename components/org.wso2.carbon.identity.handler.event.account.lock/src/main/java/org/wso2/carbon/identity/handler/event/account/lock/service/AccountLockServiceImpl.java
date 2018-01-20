/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.handler.event.account.lock.service;

import org.apache.commons.lang.math.NumberUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.Map;

/**
 * Service implementation class of {@link AccountLockService} that returns account lock states.
 */
public class AccountLockServiceImpl implements AccountLockService {

    @Override
    public boolean isAccountLocked(String domainAwareUsername, String tenantDomain) throws AccountLockServiceException {

        UserStoreManager userStoreManager = getUserStoreManager(tenantDomain);
        boolean accountLocked = getAccountLockClaimValue(domainAwareUsername, userStoreManager);
        if (accountLocked) {
            long accountUnlockTime = getAccountUnlockTimeClaimValue(domainAwareUsername, userStoreManager);
            if (accountUnlockTime != 0 && System.currentTimeMillis() >= accountUnlockTime) {
                return false;
            }
        }
        return accountLocked;
    }

    @Override
    public boolean isAccountLocked(String username, String tenantDomain, String userStoreDomain) throws
            AccountLockServiceException {

        return isAccountLocked(IdentityUtil.addDomainToName(username, userStoreDomain), tenantDomain);
    }

    private boolean getAccountLockClaimValue(String username, UserStoreManager userStoreManager) throws
            AccountLockServiceException {

        String accountLockedClaimValue = getClaimValue(username, userStoreManager, AccountConstants
                .ACCOUNT_LOCKED_CLAIM);
        return Boolean.parseBoolean(accountLockedClaimValue);
    }

    private long getAccountUnlockTimeClaimValue(String username, UserStoreManager userStoreManager) throws
            AccountLockServiceException {

        long unlockTime = 0;
        String accountUnlockTimeClaimValue = getClaimValue(username, userStoreManager, AccountConstants
                .ACCOUNT_UNLOCK_TIME_CLAIM);
        if (NumberUtils.isNumber(accountUnlockTimeClaimValue)) {
            unlockTime = Long.parseLong(accountUnlockTimeClaimValue);
        }

        return unlockTime;
    }

    private String getClaimValue(String username, UserStoreManager userStoreManager, String claimURI) throws
            AccountLockServiceException {

        try {
            Map<String, String> values = userStoreManager.getUserClaimValues(username, new String[]{claimURI},
                    UserCoreConstants.DEFAULT_PROFILE);
            return values.get(claimURI);

        } catch (UserStoreException e) {
            throw new AccountLockServiceException("Error occurred while retrieving claim: " + claimURI, e);
        }
    }

    private UserStoreManager getUserStoreManager(String tenantDomain) throws AccountLockServiceException {

        int tenantId;
        try {
            tenantId = AccountServiceDataHolder.getInstance().getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
        } catch (UserStoreException e) {
            throw new AccountLockServiceException("Could not retrieve tenant id from tenant domain: " + tenantDomain,
                    e);
        }

        if (MultitenantConstants.INVALID_TENANT_ID == tenantId) {
            throw new AccountLockServiceException("Invalid tenant domain: " + tenantDomain);
        }

        UserRealm userRealm;
        try {
            userRealm = AccountServiceDataHolder.getInstance().getRealmService().getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new AccountLockServiceException("Could not retrieve user realm for tenant domain: " + tenantDomain,
                    e);
        }

        try {
            return userRealm.getUserStoreManager();
        } catch (UserStoreException e) {
            throw new AccountLockServiceException("Could not retrieve user store for tenant domain: " + tenantDomain,
                    e);
        }
    }
}
