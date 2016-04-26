package org.wso2.carbon.identity.account.lock.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.account.lock.constants.AccountLockConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.EventMgtConstants;
import org.wso2.carbon.identity.event.EventMgtException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.mgt.store.UserIdentityDataStore;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

public class AccountLockHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(AccountLockHandler.class);

    @Override
    public boolean handleEvent(Event event) throws EventMgtException {
        Map<String, Object> eventProperties = event.getEventProperties();


        String userName = (String) eventProperties.get(EventMgtConstants.EventProperty.USER_NAME);
        UserStoreManager userStoreManager = (UserStoreManager) eventProperties.get(EventMgtConstants.EventProperty.USER_STORE_MANAGER);
        UserIdentityDataStore module = (UserIdentityDataStore) eventProperties.get(EventMgtConstants.EventProperty.MODULE);
        int tenantId = (Integer) eventProperties.get(EventMgtConstants.EventProperty.TENANT_ID);

        Map<String, String> identityProperties = getTenantConfigurations(tenantId);

        IdentityUtil.clearIdentityErrorMsg();

        if (!Boolean.parseBoolean(identityProperties.get(AccountLockConstants.ACCOUNT_LOCKED_PROPERTY))) {
            return true;
        }
        String domainName = userStoreManager.getRealmConfiguration().getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
        String usernameWithDomain = UserCoreUtil.addDomainToName(userName, domainName);
        boolean isUserExistInCurrentDomain;
        try {
            isUserExistInCurrentDomain = userStoreManager.isExistingUser(usernameWithDomain);
        } catch (UserStoreException e) {
            throw new EventMgtException("Error in accessing user store");
        }

        if (EventMgtConstants.Event.PRE_AUTHENTICATION.equals(event.getEventName())) {
            if (!isUserExistInCurrentDomain) {
                return true;
            } else {
                try {
                    if (Boolean.parseBoolean(userStoreManager.getUserClaimValue(userName,
                            AccountLockConstants.ACCOUNT_LOCKED_CLAIM, null))) {
                        int unlockTime = Integer.parseInt(userStoreManager.getUserClaimValue(userName,
                                AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, null));
                        if ((unlockTime != 0) && (System.currentTimeMillis() >= unlockTime)) {

                            Map<String, String> newClaims = new HashMap<>();
                            newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, Boolean.FALSE.toString());
                            newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                            userStoreManager.setUserClaimValues(userName, newClaims, null);
                        } else {
                            String errorMsg = "User account is locked for user : " + userName
                                    + ". cannot login until the account is unlocked ";
                            throw new EventMgtException(UserCoreConstants.ErrorCode.USER_IS_LOCKED + " "
                                    + errorMsg);
                        }
                    }
                } catch (UserStoreException e) {
                    throw new EventMgtException("Error while retrieving account lock claim value", e);
                }
            }
        } else if (EventMgtConstants.Event.POST_AUTHENTICATION.equals(event.getEventName())) {
            if ((Boolean)eventProperties.get(EventMgtConstants.EventProperty.OPERATION_STATUS)) {
                Map<String, String> newClaims = new HashMap<>();
                newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, "0");
                newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, "0");
                newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, "false");
                try {
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new EventMgtException("Error while setting up user identity claims.", e);
                }
            } else {
                try {
                    int numberOffailedAttermpts = Integer.parseInt(userStoreManager.getUserClaimValue(userName,
                            AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, null)) + 1;
                    Map<String, String> newClaims = new HashMap<>();
                    newClaims.put(AccountLockConstants.FAILED_LOGIN_ATTEMPTS_CLAIM, numberOffailedAttermpts + "");
                    if (numberOffailedAttermpts >= Integer.parseInt(identityProperties.get
                            (AccountLockConstants.FAILED_LOGIN_ATTEMPTS_PROPERTY))) {
                        newClaims.put(AccountLockConstants.ACCOUNT_LOCKED_CLAIM, "true");
                        String unlockTimeProperty = identityProperties.get(AccountLockConstants
                                .ACCOUNT_UNLOCK_TIME_PROPERTY);
                        if (!"0".equals(unlockTimeProperty)) {
                            long unlockTime = System.currentTimeMillis() + Integer.parseInt(unlockTimeProperty) * 60 * 1000L;
                            newClaims.put(AccountLockConstants.ACCOUNT_UNLOCK_TIME_CLAIM, unlockTime + "");
                        }
                    }
                    userStoreManager.setUserClaimValues(userName, newClaims, null);
                } catch (UserStoreException e) {
                    throw new EventMgtException("Error while locking account.", e);
                }
            }
        }
        return true;
    }

    @Override
    public void init() throws EventMgtException {
    }

    @Override
    public String getModuleName() {
        return "accountLock";
    }
}
