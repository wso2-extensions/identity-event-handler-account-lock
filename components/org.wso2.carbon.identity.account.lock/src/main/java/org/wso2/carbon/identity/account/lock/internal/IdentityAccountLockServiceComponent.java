package org.wso2.carbon.identity.account.lock.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.account.lock.handler.AccountLockHandler;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.mgt.IdentityGovernanceService;

/**
 * @scr.component name="org.wso2.carbon.identity.account.lock.internal.IdentityAccountLockServiceComponent"
 * immediate="true
 * @scr.reference name="IdentityGovernanceService"
 * interface="org.wso2.carbon.identity.mgt.IdentityGovernanceService" cardinality="1..1"
 * policy="dynamic" bind="setIdentityGovernanceService" unbind="unsetIdentityGovernanceService"
 */
public class IdentityAccountLockServiceComponent {

    private static Log log = LogFactory.getLog(IdentityAccountLockServiceComponent.class);

    protected void activate(ComponentContext context) {

        IdentityAccountLockServiceDataHolder.getInstance().setBundleContext(context.getBundleContext());
        AccountLockHandler handler = new AccountLockHandler();
        context.getBundleContext().registerService(AbstractEventHandler.class.getName(),
                handler, null);
        //context.getBundleContext().registerService(IdentityGovernanceConnector.class.getName(), handler, null);
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

}
