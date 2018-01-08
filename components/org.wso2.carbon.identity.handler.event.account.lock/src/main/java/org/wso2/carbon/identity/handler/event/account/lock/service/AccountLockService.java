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

import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;

/**
 * Service interface that returns account lock states.
 */
public interface AccountLockService {

    /**
     * Returns if account is locked or not as a boolean.
     * <p>
     * Account is considered to be unlocked, if account lock claim (http://wso2.org/claims/identity/accountLocked) is
     * set to 'false' or, if account unlock time claim (http://wso2.org/claims/identity/unlockTime) is not zero and
     * current time exceeds account unlock time claim value when account lock claim is set to 'true'.
     * Unless if account lock claim is set to 'true' account is always considered to be locked.
     *
     * @param domainAwareUsername username with user store domain
     * @param tenantDomain        tenant domain of the user
     * @return true if the account is locked and false if the account is unlocked
     */
    boolean isAccountLocked(String domainAwareUsername, String tenantDomain) throws AccountLockServiceException;

    /**
     * Returns if account is locked or not as a boolean.
     * <p>
     * Account is considered to be unlocked, if account lock claim (http://wso2.org/claims/identity/accountLocked) is
     * set to 'false' or, if account unlock time claim (http://wso2.org/claims/identity/unlockTime) is not zero and
     * current time exceeds account unlock time claim value when account lock claim is set to 'true'.
     * Unless if account lock claim is set to 'true' account is always considered to be locked.
     *
     * @param username        username without user store domain
     * @param tenantDomain    tenant domain of the user
     * @param userStoreDomain user store domain of the user
     * @return
     * @throws AccountLockServiceException
     */
    boolean isAccountLocked(String username, String tenantDomain, String userStoreDomain) throws
            AccountLockServiceException;
}
