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

package org.wso2.carbon.identity.account.lock.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.account.lock.handler.AccountLockHandler;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.services.EventMgtService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

/**
 * @scr.component name="org.wso2.carbon.identity.account.lock.internal.IdentityAccountLockServiceComponent"
 * immediate="true
 * @scr.reference name="IdentityGovernanceService"
 * interface="org.wso2.carbon.identity.governance.IdentityGovernanceService" cardinality="1..1"
 * policy="dynamic" bind="setIdentityGovernanceService" unbind="unsetIdentityGovernanceService"
 * @scr.reference name="EventMgtService"
 * interface="org.wso2.carbon.identity.event.services.EventMgtService" cardinality="1..1"
 * policy="dynamic" bind="setEventMgtService" unbind="unsetEventMgtService"
 */
public class IdentityAccountLockServiceComponent {

    private static Log log = LogFactory.getLog(IdentityAccountLockServiceComponent.class);

    protected void activate(ComponentContext context) {

        IdentityAccountLockServiceDataHolder.getInstance().setBundleContext(context.getBundleContext());
        AccountLockHandler handler = new AccountLockHandler();
        context.getBundleContext().registerService(AbstractEventHandler.class.getName(), handler, null);
        if (log.isDebugEnabled()) {
            log.debug("Identity Management Listener is enabled");
        }
    }

    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Identity Management bundle is de-activated");
        }
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {
        IdentityAccountLockServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {
        IdentityAccountLockServiceDataHolder.getInstance().setIdentityGovernanceService(idpManager);
    }

    protected void unsetEventMgtService(EventMgtService eventManager) {
        IdentityAccountLockServiceDataHolder.getInstance().setEventMgtService(null);
    }

    protected void setEventMgtService(EventMgtService eventManager) {
        IdentityAccountLockServiceDataHolder.getInstance().setEventMgtService(eventManager);
    }

}
