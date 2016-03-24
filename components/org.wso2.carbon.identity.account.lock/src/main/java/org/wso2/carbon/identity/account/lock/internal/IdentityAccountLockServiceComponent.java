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

//        context.getBundleContext().registerService(EventHandler.class.getName(),
//                new AccountLockEventHandler(), null);
        context.getBundleContext().registerService(EventHandler.class.getName(),
                new AccountLockHandler(), null);
//        try {
//            EventMgtServiceDataHolder.getInstance().setEventMgtService(new EventMgtServiceImpl(eventHandlerList,
//                    Integer.parseInt(EventMgtConfigBuilder.getInstance().getThreadPoolSize())));
//        } catch (EventMgtException e) {
//            log.error("Error while initiating IdentityMgtService.");
//        }
//        init();
//        listener = new EventMgtListener();
//        serviceRegistration =
//                context.getBundleContext().registerService(UserOperationEventListener.class.getName(),
//                        listener, null);
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
