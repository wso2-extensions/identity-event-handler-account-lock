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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.email.mgt.EmailTemplateManager;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthenticationHandler;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.AccountDisableHandler;
import org.wso2.carbon.identity.handler.event.account.lock.AccountLockHandler;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.handlers.PostAuthnFailedLockoutClaimHandler;
import org.wso2.carbon.identity.handler.event.account.lock.listener.AccountLockTenantMgtListener;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountDisableServiceImpl;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockServiceImpl;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "handler.event.account.lock",
        immediate = true)
public class AccountServiceComponent {

    private static final Log log = LogFactory.getLog(AccountServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
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
            AccountLockService accountLockService = new AccountLockServiceImpl();
            context.getBundleContext().registerService(AccountLockService.class.getName(), accountLockService, null);
            if (log.isDebugEnabled()) {
                log.debug("AccountLockService is registered");
            }
            AccountDisableService accountDisableService = new AccountDisableServiceImpl();
            context.getBundleContext().registerService(AccountDisableService.class.getName(), accountDisableService,
                    null);
            if (log.isDebugEnabled()) {
                log.debug("AccountDisableService is registered");
            }
            AccountLockTenantMgtListener accountLockTenantMgtListener = new AccountLockTenantMgtListener();
            context.getBundleContext().registerService(TenantMgtListener.class, accountLockTenantMgtListener, null);
            if (log.isDebugEnabled()) {
                log.debug("AccountLockTenantMgtListener is registered");
            }
            PostAuthenticationHandler postAuthnFailedLockoutClaimHandler = PostAuthnFailedLockoutClaimHandler
                    .getInstance();
            context.getBundleContext()
                    .registerService(PostAuthenticationHandler.class.getName(), postAuthnFailedLockoutClaimHandler, null);
            try {
                UserStoreManager userStoreManager = AccountServiceDataHolder.getInstance().getRealmService()
                        .getBootstrapRealm().getUserStoreManager();
                if (!userStoreManager.isExistingRole(AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE)) {
                    userStoreManager.addRole(AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE, null, null, false);
                }
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                log.error(String.format("Error while adding role: %s .", AccountConstants.ACCOUNT_LOCK_BYPASS_ROLE), e);
            }
        } catch (Exception e) {
            log.error("Error while activating account lock handler bundle.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("AccountLock bundle is de-activated");
        }
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AccountServiceDataHolder.getInstance().setIdentityGovernanceService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        AccountServiceDataHolder.getInstance().setIdentityGovernanceService(identityGovernanceService);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        AccountServiceDataHolder.getInstance().setIdentityEventService(null);
    }

    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService eventService) {

        AccountServiceDataHolder.getInstance().setIdentityEventService(eventService);
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        AccountServiceDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        AccountServiceDataHolder.getInstance().setRealmService(null);
    }

    @Reference(name = "emailTemplateManager.service",
            service = org.wso2.carbon.email.mgt.EmailTemplateManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEmailTemplateManager")
    protected void setEmailTemplateManager(EmailTemplateManager emailTemplateManager) {

        if (log.isDebugEnabled()) {
            log.debug("Email Template Manager is registered in Account service.");
        }
        AccountServiceDataHolder.getInstance().setEmailTemplateManager(emailTemplateManager);
    }

    protected void unsetEmailTemplateManager(EmailTemplateManager emailTemplateManager) {

        if (log.isDebugEnabled()) {
            log.debug("Email Template Manager is unregistered in Account service.");
        }
        AccountServiceDataHolder.getInstance().setEmailTemplateManager(null);
    }
}
