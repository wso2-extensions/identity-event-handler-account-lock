/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.handler.event.account.lock;

/**
 * Audit related Constants.
 */
public class AuditConstants {

    public static final String AUDIT_MESSAGE = "Initiator : %s | Action : %s | Target : %s | Data : %s | Result : %s ";
    public static final String AUDIT_SUCCESS = "Success";
    public static final String AUDIT_FAILED = "Failed";
    public static final String USER_AGENT_QUERY_KEY = "User-Agent";
    public static final String USER_AGENT_KEY = "User Agent";
    public static final String REMOTE_ADDRESS_QUERY_KEY = "remoteAddress";
    public static final String REMOTE_ADDRESS_KEY = "RemoteAddress";
    public static final String SERVICE_PROVIDER_KEY = "ServiceProviderName";
    public static final String SERVICE_PROVIDER_QUERY_KEY = "serviceProvider";
    public static final String ERROR_MESSAGE_KEY = "Error Message";
    public static final String REGISTRY_SYSTEM_USERNAME = "wso2.system.user";
    public static final String ACCOUNT_LOCKED = "Account Lock";
    public static final String ACCOUNT_UNLOCKED = "Account Unlock";
    public static final String USER_STORE_DOMAIN = "UserStoreDomain";
    public static final String ACCOUNT_DISABLED = "Account Disable";
    public static final String ACCOUNT_ENABLED = "Account Enable";
    public static final String IS_MODIFIED_STATUS = "ModifiedStatus";
}
