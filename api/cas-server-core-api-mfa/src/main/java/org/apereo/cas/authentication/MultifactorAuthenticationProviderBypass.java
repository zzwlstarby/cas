package org.apereo.cas.authentication;

import org.apereo.cas.services.RegisteredService;

import org.springframework.core.Ordered;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;

/**
 * This is {@link MultifactorAuthenticationProviderBypass}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@FunctionalInterface
public interface MultifactorAuthenticationProviderBypass extends Serializable, Ordered {

    /**
     * bypass mfa authn attribute.
     */
    String AUTHENTICATION_ATTRIBUTE_BYPASS_MFA = "bypassMultifactorAuthentication";

    /**
     * Eval current bypass rules for the provider.
     *
     * @param authentication    the authentication
     * @param registeredService the registered service in question
     * @param provider          the provider
     * @param request           the request
     * @return false is request isn't supported and can be bypassed. true otherwise.
     */
    boolean shouldExecute(Authentication authentication, RegisteredService registeredService,
                          MultifactorAuthenticationProvider provider,
                          HttpServletRequest request);

    /**
     * Method will remove any previous bypass set in the authentication.
     *
     * @param authentication - the authentication
     */
    default void clearBypass(final Authentication authentication) {
        authentication.getAttributes().remove(AUTHENTICATION_ATTRIBUTE_BYPASS_MFA);
    }

    /**
     * Method will set the bypass into the authentication.
     *
     * @param authentication - the authentication
     * @param result - the result
     */
    default void setBypass(final Authentication authentication,
                           final MultifactorAuthenticationBypassResult result) {
        authentication.addAttribute(AUTHENTICATION_ATTRIBUTE_BYPASS_MFA, result);
    }

    @Override
    default int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
