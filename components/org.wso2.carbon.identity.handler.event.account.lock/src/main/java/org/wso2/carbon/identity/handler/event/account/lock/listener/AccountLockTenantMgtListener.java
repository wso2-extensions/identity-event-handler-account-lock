/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.handler.event.account.lock.listener;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.AbstractIdentityTenantMgtListener;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;

/**
 * Tenant activation listener for Account Lock component to do the task when the tenant get create.
 */
public class AccountLockTenantMgtListener extends AbstractIdentityTenantMgtListener {

    private static Log log = LogFactory.getLog(AccountLockTenantMgtListener.class);

    @Override
    public void onTenantInitialActivation(int tenantId) throws StratosException {

        if (log.isDebugEnabled()) {
            log.debug("AccountLockTenantMgtListener is fired for Tenant ID : " + tenantId);
        }

        try {
            AccountServiceDataHolder.getInstance().getRealmService().getTenantUserRealm(tenantId).
                    getUserStoreManager().addRole(AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE, null, null, false);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error(String.format("Error while adding role: %s on Tenant: %d",
                    AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE, tenantId), e);
        }
    }

    @Override
    public int getListenerOrder() {

        return 0;
    }
}
