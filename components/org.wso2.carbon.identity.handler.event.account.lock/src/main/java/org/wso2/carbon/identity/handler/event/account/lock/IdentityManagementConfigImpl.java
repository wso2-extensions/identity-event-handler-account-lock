/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.constants.IdentityManagementEndpointConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * class for store identity management endpoint attributes
 */
public class IdentityManagementConfigImpl implements IdentityConnectorConfig {

    private static final String connectorName = "identity-management";
    private static final String label = "label";

    @Override
    public String getName() {
        return connectorName;
    }

    public String getFriendlyName() {
        return "Identity Management Endpoints";
    }

    @Override
    public String getCategory() {
        return "DEFAULT";
    }

    @Override
    public String getSubCategory() {
        return "DEFAULT";
    }

    @Override
    public int getOrder() {
        return 0;
    }

    public Map<String, String> getPropertyNameMapping() {
        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(IdentityManagementEndpointConstants.RECOVERY_REST_ENDPOINT, "Recovery Rest Endpoint");
        nameMapping.put(IdentityManagementEndpointConstants.SELF_REGISTRATION_ENDPOINT, "Self Registration Endpoint");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        return Collections.emptyMap();
    }

    public String[] getPropertyNames() {
        List<String> properties = new ArrayList<>();
        properties.add(IdentityManagementEndpointConstants.RECOVERY_REST_ENDPOINT);
        properties.add(IdentityManagementEndpointConstants.SELF_REGISTRATION_ENDPOINT);
        return properties.toArray(new String[properties.size()]);
    }

    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        String tenantContext = "";

        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)) {
            tenantContext = MultitenantConstants.TENANT_AWARE_URL_PREFIX + "/" + tenantDomain + "/";
        }
        String recoveryRestEndpoint = IdentityUtil.getProperty
                (IdentityConstants.IdentityManagement.Recovery_REST_EP_URL);
        String selfRegistrationEndpoint = IdentityUtil.getProperty(IdentityConstants
                .IdentityManagement.Self_Registration_EP_URL);
        if (StringUtils.isBlank(recoveryRestEndpoint)) {
            recoveryRestEndpoint =
                    IdentityUtil.getServerURL(IdentityConstants.IdentityManagement.Recovery_REST_EP, true, false);
        }
        if (StringUtils.isNotBlank(selfRegistrationEndpoint)) {
            selfRegistrationEndpoint = selfRegistrationEndpoint
                    .replace(IdentityConstants.IdentityManagement.Self_Registration_EP, tenantContext +
                            IdentityConstants.IdentityManagement.Self_Registration_EP);
        } else {
            selfRegistrationEndpoint =
                    IdentityUtil.getServerURL(tenantContext + IdentityConstants.IdentityManagement.Self_Registration_EP,
                            true, true);
        }
        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(IdentityManagementEndpointConstants.RECOVERY_REST_ENDPOINT, recoveryRestEndpoint);
        defaultProperties.put(IdentityManagementEndpointConstants.SELF_REGISTRATION_ENDPOINT, selfRegistrationEndpoint);
        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {
        return Collections.emptyMap();
    }

    @Override
    public Map<String, String> getPropertyTypeMapping() {
        Map<String, String> typeMap = new HashMap<>();
        typeMap.put(IdentityManagementEndpointConstants.RECOVERY_REST_ENDPOINT, label);
        typeMap.put(IdentityManagementEndpointConstants.SELF_REGISTRATION_ENDPOINT, label);
        return typeMap;
    }

}
