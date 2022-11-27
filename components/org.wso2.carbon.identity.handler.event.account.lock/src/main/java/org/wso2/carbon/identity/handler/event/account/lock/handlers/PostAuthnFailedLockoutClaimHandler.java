
/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.handler.event.account.lock.handlers;

import static org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus.SUCCESS_COMPLETED;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.ACCOUNT_LOCKED_CLAIM;
import static org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants.FAILED_LOGIN_LOCKOUT_COUNT_CLAIM;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.PostAuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AbstractPostAuthnHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.PostAuthnHandlerFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkErrorConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.constants.AccountConstants;
import org.wso2.carbon.identity.handler.event.account.lock.internal.AccountServiceDataHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Handles resetting failed login lockout count upon after a successful authentication flow.
 */
public class PostAuthnFailedLockoutClaimHandler extends AbstractPostAuthnHandler {

    private static final Log log = LogFactory.getLog(PostAuthnFailedLockoutClaimHandler.class);
    private static volatile PostAuthnFailedLockoutClaimHandler instance = new PostAuthnFailedLockoutClaimHandler();
    private static final String handlerName = "PostAuthnFailedLockoutClaimHandler";
    private static final String LOCAL_AUTHENTICATOR = "LOCAL";
    private static final String ERROR_WHILE_GETTING_USER_STORE_MANAGER_ERROR_CODE = "80022";
    public static final String ACCOUNT_LOCK_HANDLER_ENABLE_PROPERTY = "account.lock.handler.enable";

    /**
     * To get an instance of {@link PostAuthnFailedLockoutClaimHandler}.
     *
     * @return an instance of PostJITProvisioningHandler.
     */
    public static PostAuthnFailedLockoutClaimHandler getInstance() {

        return instance;
    }

    /**
     * To avoid creation of multiple instances of this handler.
     */
    protected PostAuthnFailedLockoutClaimHandler() {

    }

    @Override
    public int getPriority() {

        int priority = super.getPriority();
        if (priority == -1) {
            priority = 21;
        }
        return priority;
    }

    @Override
    public String getName() {

        return handlerName;
    }

    @Override
    public PostAuthnHandlerFlowStatus handle(HttpServletRequest request, HttpServletResponse response,
                                             AuthenticationContext context) throws PostAuthenticationFailedException {

        AuthenticatedUser authenticatedUser = context.getSequenceConfig().getAuthenticatedUser();
        try {
            /* Check whether account locking enabled and user is a local user.
            Account locking is not done for federated flows. */
            if (authenticatedUser.isFederatedUser() || isAccountLockingDisabled(authenticatedUser.getTenantDomain())) {
                return SUCCESS_COMPLETED;
            }
            String usernameWithDomain = IdentityUtil.addDomainToName(
                    authenticatedUser.getUserName(), authenticatedUser.getUserStoreDomain());
            UserRealm realm = getUserRealm(authenticatedUser.getTenantDomain());
            UserStoreManager userStoreManager = realm.getUserStoreManager();
            if (userStoreManager.isExistingUser(usernameWithDomain)) {
                Map<String, String> claimValues = getUserClaims(userStoreManager, usernameWithDomain);
                String accountLockClaim = claimValues.get(ACCOUNT_LOCKED_CLAIM);
                if (accountLockClaim != null && !Boolean.parseBoolean(accountLockClaim)) {
                    String failedLoginLockoutCount =
                            claimValues.get(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM);
                    // check if the value is already not zero
                    if (NumberUtils.isNumber(failedLoginLockoutCount) && Integer.parseInt(failedLoginLockoutCount) > 0) {
                        Map<String, String> updatedClaims = new HashMap<>();
                        updatedClaims.put(FAILED_LOGIN_LOCKOUT_COUNT_CLAIM, "0");
                        userStoreManager.setUserClaimValues(usernameWithDomain, updatedClaims, null);
                    }
                }
            }

        } catch (UserStoreException e) {
            throw new PostAuthenticationFailedException(ERROR_WHILE_GETTING_USER_STORE_MANAGER_ERROR_CODE,
                    "Error occurred while retrieving user store manager.");
        } catch (FrameworkException e) {
            throw new PostAuthenticationFailedException(
                    FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_GETTING_CLAIM_MAPPINGS.getCode(),
                    FrameworkErrorConstants.ErrorMessages.ERROR_WHILE_GETTING_CLAIM_MAPPINGS.getMessage(), e);
        }

        return SUCCESS_COMPLETED;
    }

    private UserRealm getUserRealm(String tenantDomain) throws UserStoreException {

        RealmService realmService = AccountServiceDataHolder.getInstance().getRealmService();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        return (UserRealm) realmService.getTenantUserRealm(tenantId);
    }

    private Map<String, String> getUserClaims(UserStoreManager userStoreManager, String authenticatedUser)
            throws FrameworkException {

        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(
                    authenticatedUser,
                    new String[] {FrameworkConstants.ACCOUNT_LOCKED_CLAIM_URI, FAILED_LOGIN_LOCKOUT_COUNT_CLAIM},
                    null);
            return claimValues;

        } catch (UserStoreException e) {
            throw new FrameworkException("Error occurred while retrieving user claims", e);
        }
    }

    private boolean isAccountLockingDisabled(String tenantDomain) throws FrameworkException {

        Property accountLockConfigProperty = FrameworkUtils.getResidentIdpConfiguration(
                AccountConstants.ACCOUNT_LOCK_MAX_FAILED_ATTEMPTS_PROPERTY, tenantDomain);

        return !(accountLockConfigProperty != null && Boolean.parseBoolean(accountLockConfigProperty.getValue()));
    }
}