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

package org.wso2.carbon.identity.handler.event.account.lock.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.AccountDisableHandler;
import org.wso2.carbon.identity.handler.event.account.lock.AccountLockHandler;
import org.wso2.carbon.identity.handler.event.account.lock.IdentityManagementConfigImpl;
import org.wso2.carbon.identity.handler.event.account.lock.XACMLEndpointConfigImpl;

/**
 * @scr.component name="handler.event.account.lock"
 * immediate="true"
 * @scr.reference name="IdentityGovernanceService"
 * interface="org.wso2.carbon.identity.governance.IdentityGovernanceService" cardinality="1..1"
 * policy="dynamic" bind="setIdentityGovernanceService" unbind="unsetIdentityGovernanceService"
 * @scr.reference name="EventMgtService"
 * interface="org.wso2.carbon.identity.event.services.IdentityEventService" cardinality="1..1"
 * policy="dynamic" bind="setIdentityEventService" unbind="unsetIdentityEventService"
 */
public class AccountServiceComponent {

    private static Log log = LogFactory.getLog(AccountServiceComponent.class);

    protected void activate(ComponentContext context) {

        AccountServiceDataHolder.getInstance().setBundleContext(context.getBundleContext());
        AccountLockHandler accountLockHandler = new AccountLockHandler();
        context.getBundleContext().registerService(AbstractEventHandler.class.getName(), accountLockHandler, null);
        if (log.isDebugEnabled()) {
            log.debug("AccountLockHandler is registered");
        }
        AccountDisableHandler accountDisableHandler = new AccountDisableHandler();
        context.getBundleContext().registerService(AbstractEventHandler.class.getName(), accountDisableHandler, null);
        if (log.isDebugEnabled()) {
            log.debug("AccountDisableHandler is registered");
        }
        XACMLEndpointConfigImpl xacmlEndpointConfigImpl = new XACMLEndpointConfigImpl();
        context.getBundleContext().registerService(IdentityConnectorConfig.class.getName(), xacmlEndpointConfigImpl, null);
        if (log.isDebugEnabled()) {
            log.debug("XACMLEndpointConfigImpl is registered");
        }
        IdentityManagementConfigImpl identityManagementConfigImpl = new IdentityManagementConfigImpl();
        context.getBundleContext().registerService(IdentityConnectorConfig.class.getName(),
                identityManagementConfigImpl, null);
        if (log.isDebugEnabled()) {
            log.debug("IdentityManagementConfigImpl is registered");
        }
    }

    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("AccountLock bundle is de-activated");
        }
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {
        AccountServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {
        AccountServiceDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {
        AccountServiceDataHolder.getInstance().setIdentityEventService(null);
    }

    protected void setIdentityEventService(IdentityEventService eventService) {
        AccountServiceDataHolder.getInstance().setIdentityEventService(eventService);
    }

}
