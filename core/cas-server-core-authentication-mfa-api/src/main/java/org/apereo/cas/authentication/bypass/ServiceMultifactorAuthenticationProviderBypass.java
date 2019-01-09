package org.apereo.cas.authentication.bypass;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.authentication.MultifactorAuthenticationProviderBypass;
import org.apereo.cas.configuration.model.support.mfa.MultifactorAuthenticationProviderBypassProperties;
import org.apereo.cas.services.RegisteredService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletRequest;

/**
 * Multifactor Bypass Provider based on Service Multifactor Policy.
 *
 * @author Travis Schmidt
 * @since 6.0
 */
@Slf4j
@RequiredArgsConstructor
public class ServiceMultifactorAuthenticationProviderBypass implements MultifactorAuthenticationProviderBypass {

    private final MultifactorAuthenticationProviderBypassProperties bypassProperties;

    @Override
    public boolean shouldExecute(final Authentication authentication,
                                 final RegisteredService registeredService,
                                 final MultifactorAuthenticationProvider provider,
                                 final HttpServletRequest request) {

        if (registeredService != null
                && registeredService.getMultifactorPolicy() != null
                && registeredService.getMultifactorPolicy().isBypassEnabled()) {
            return false;
        }
        return true;
    }
}
