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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockRuntimeException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;

public class AccountUtil {

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

}