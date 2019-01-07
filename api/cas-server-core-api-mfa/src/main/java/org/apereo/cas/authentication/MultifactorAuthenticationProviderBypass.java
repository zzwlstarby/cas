package org.apereo.cas.authentication;

import org.apereo.cas.services.RegisteredService;

import org.apache.commons.lang3.tuple.Pair;
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
     * bypass mfa for provider id authn attribute.
     */
    String AUTHENTICATION_ATTRIBUTE_BYPASS_MFA_PROVIDER = "bypassedMultifactorAuthenticationProviderId";

    /**
     * bypass mfa origin.
     */
    String AUTHENTICATION_ATTTRIBUTE_BYPASS_MFA_ORIGIN = "bypassedMultifactrorAuthenticationOrigin";

    /**
     * Eval current bypass rules for the provider.
     *
     * @param authentication    the authentication
     * @param registeredService the registered service in question
     * @param provider          the provider
     * @param request           the request
     * @return false is request isn't supported and can be bypassed. true otherwise.
     */
    Pair<Boolean, String> shouldMultifactorAuthenticationProviderExecute(Authentication authentication, RegisteredService registeredService,
                                                                         MultifactorAuthenticationProvider provider,
                                                                         HttpServletRequest request);

    /**
     * Method will remove any previous bypass set in the authentication.
     *
     * @param authentication - the authentication
     */
    default void updateAuthenticationToForgetBypass(final Authentication authentication) {
        authentication.addAttribute(AUTHENTICATION_ATTRIBUTE_BYPASS_MFA, Boolean.FALSE);
    }

    /**
     * Method will set the bypass into the authentication.
     *
     * @param authentication - the authentication
     * @param provider - the provider
     * @param bypassOrigin - the origin of the bypass
     * */
    default void updateAuthenticationToRememberBypass(final Authentication authentication,
                                                      final MultifactorAuthenticationProvider provider,
                                                      final String bypassOrigin) {
        authentication.addAttribute(AUTHENTICATION_ATTRIBUTE_BYPASS_MFA, Boolean.TRUE);
        authentication.addAttribute(AUTHENTICATION_ATTRIBUTE_BYPASS_MFA_PROVIDER, provider.getId());
        authentication.addAttribute(AUTHENTICATION_ATTTRIBUTE_BYPASS_MFA_ORIGIN, bypassOrigin);
    }

    @Override
    default int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}
