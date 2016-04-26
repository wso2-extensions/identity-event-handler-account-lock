package org.wso2.carbon.identity.account.lock.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.account.lock.handler.AccountLockHandler;
import org.wso2.carbon.identity.event.handler.EventHandler;

/**
 * @scr.component name="org.wso2.carbon.identity.account.lock.internal.IdentityAccountLockServiceComponent"
 * immediate="true
 */
public class IdentityAccountLockServiceComponent {

    private static Log log = LogFactory.getLog(IdentityAccountLockServiceComponent.class);

    protected void activate(ComponentContext context) {
        context.getBundleContext().registerService(EventHandler.class.getName(),
                new AccountLockHandler(), null);
        if (log.isDebugEnabled()) {
            log.debug("Identity Management Listener is enabled");
        }
    }


    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("Identity Management bundle is de-activated");
        }
    }

}
