package org.apereo.cas.authentication.bypass;

import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.MultifactorAuthenticationProvider;
import org.apereo.cas.authentication.MultifactorAuthenticationProviderBypass;
import org.apereo.cas.services.RegisteredService;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

/**
 * Class used to Chain multiple {@link MultifactorAuthenticationProviderBypass} implementations.
 *
 * @author Travis Schmidt
 * @since 5.3.4
 */
public class ChainingMultifactorAuthenticationBypassProvider implements MultifactorAuthenticationProviderBypass {

    private static final long serialVersionUID = 2397239625822397286L;
    private final List<MultifactorAuthenticationProviderBypass> bypasses = new ArrayList<>();

    @Override
    public boolean shouldMultifactorAuthenticationProviderExecute(final Authentication authentication,
                                                                  final RegisteredService registeredService,
                                                                  final MultifactorAuthenticationProvider provider,
                                                                  final HttpServletRequest request) {

        return bypasses.stream()
                .map(bypass -> bypass.shouldMultifactorAuthenticationProviderExecute(authentication, registeredService, provider, request))
                .filter(p -> !p)
                .findFirst().orElse(true);
    }

    /**
     * Add bypass provider.
     *
     * @param bypass - the bypass provider
     */
    public void addBypass(final MultifactorAuthenticationProviderBypass bypass) {
        this.bypasses.add(bypass);
    }

    /**
     * Size.
     *
     * @return the int
     */
    public int size() {
        return bypasses.size();
    }
}
