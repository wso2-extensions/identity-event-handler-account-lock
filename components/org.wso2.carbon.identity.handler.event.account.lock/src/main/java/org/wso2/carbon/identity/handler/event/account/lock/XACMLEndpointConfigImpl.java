/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.handler.event.account.lock.constants.XACMLEndpointConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;


import java.util.*;

public class XACMLEndpointConfigImpl implements IdentityConnectorConfig {

    private static String connectorName = "xacml";

    @Override
    public String getName() {
        return connectorName;
    }

    public String getFriendlyName() {
        return "XACML Endpoints";
    }

    @Override
    public String getCategory() {
        return "Inbound Authorization Endpoints";
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
        nameMapping.put(XACMLEndpointConstants.XACML_DISCOVERY_ENDPOINT, "Discovery Endpoint");
        nameMapping.put(XACMLEndpointConstants.XACML_PDP_ENDPOINT, "PDP Endpoint");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {
        Map<String,String> descriptionMap = new HashMap<>();
        descriptionMap.put(XACMLEndpointConstants.XACML_DISCOVERY_ENDPOINT, "endpoint");
        descriptionMap.put(XACMLEndpointConstants.XACML_PDP_ENDPOINT, "endpoint");
        return descriptionMap;
    }

    public String[] getPropertyNames() {
        List<String> properties = new ArrayList<>();
        properties.add(XACMLEndpointConstants.XACML_DISCOVERY_ENDPOINT);
        properties.add(XACMLEndpointConstants.XACML_PDP_ENDPOINT);
        return properties.toArray(new String[properties.size()]);
    }

    public Properties getDefaultPropertyValues(String tenantDomain) throws IdentityGovernanceException {
        String tenantContext = "";

        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)) {
            tenantContext = MultitenantConstants.TENANT_AWARE_URL_PREFIX + "/" + tenantDomain + "/";
        }
        String xacmlPDPEndpoint = IdentityUtil.getProperty(IdentityConstants.XACML.PDP_EP_URL);
        String xacmlDiscoveryEndpoint = IdentityUtil.getProperty(IdentityConstants.XACML.Discovery_EP_URL);
        if (StringUtils.isBlank(xacmlPDPEndpoint)) {
            xacmlPDPEndpoint = IdentityUtil.getServerURL(IdentityConstants.XACML.PDP_EP, true, false);
        }
        if (StringUtils.isNotBlank(xacmlDiscoveryEndpoint)) {
            xacmlDiscoveryEndpoint = xacmlDiscoveryEndpoint.replace(IdentityConstants.XACML.Discovery_EP, tenantContext +
                    IdentityConstants.XACML.Discovery_EP);
        } else {
            xacmlDiscoveryEndpoint = IdentityUtil.getServerURL(tenantContext + IdentityConstants.XACML.Discovery_EP,
                    true, true);
        }
        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(XACMLEndpointConstants.XACML_PDP_ENDPOINT, xacmlPDPEndpoint);
        defaultProperties.put(XACMLEndpointConstants.XACML_DISCOVERY_ENDPOINT, xacmlDiscoveryEndpoint);
        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    public Map<String, String> getDefaultPropertyValues(String[] propertyNames, String tenantDomain)
            throws IdentityGovernanceException {
        return null;
    }

}

