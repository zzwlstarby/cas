package org.apereo.cas.authentication;

import org.apereo.cas.configuration.model.support.mfa.MultifactorAuthenticationProviderBypassProperties;
import org.apereo.cas.services.RegisteredService;
import org.apereo.cas.util.scripting.WatchableGroovyScriptResource;

import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.tuple.Pair;

import javax.servlet.http.HttpServletRequest;

/**
 * This is {@link GroovyMultifactorAuthenticationProviderBypass}.
 *
 * @author Misagh Moayyed
 * @since 5.2.0
 */
@Slf4j
public class GroovyMultifactorAuthenticationProviderBypass implements MultifactorAuthenticationProviderBypass {
    private static final long serialVersionUID = -4909072898415688377L;

    private final transient WatchableGroovyScriptResource watchableScript;

    public GroovyMultifactorAuthenticationProviderBypass(final MultifactorAuthenticationProviderBypassProperties bypass) {
        val groovyScript = bypass.getGroovy().getLocation();
        this.watchableScript = new WatchableGroovyScriptResource(groovyScript);
    }

    @Override
    public Pair<Boolean, String> shouldMultifactorAuthenticationProviderExecute(final Authentication authentication,
                                                                                final RegisteredService registeredService,
                                                                                final MultifactorAuthenticationProvider provider,
                                                                                final HttpServletRequest request) {
        try {
            val principal = authentication.getPrincipal();
            LOGGER.debug("Evaluating multifactor authentication bypass properties for principal [{}], "
                    + "service [{}] and provider [{}] via Groovy script [{}]",
                principal.getId(), registeredService, provider, watchableScript.getResource());
            val args = new Object[]{authentication, principal, registeredService, provider, LOGGER, request};
            val shouldExecute = watchableScript.execute(args, Boolean.class);
            if (!shouldExecute) {
                return Pair.of(Boolean.FALSE, "GROOVY");
            }
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return Pair.of(Boolean.TRUE, null);
    }
}
