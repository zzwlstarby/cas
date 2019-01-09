package org.apereo.cas.authentication.bypass;

import org.apereo.cas.authentication.MultifactorAuthenticationBypassResult;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.ZonedDateTime;

/**
 * Result stored in Authentication for a bypass MFA.
 *
 * @author TravisSchmidt
 * @since 6.0
 */
@Getter
@Setter
@AllArgsConstructor
public class DefaultMultifactorAuthenticatonBypassResult implements MultifactorAuthenticationBypassResult {

    private final String providerId;
    private final String origin;
    private ZonedDateTime bypassSetAt;
    private ZonedDateTime bypassExpiresAt;

    public DefaultMultifactorAuthenticatonBypassResult(final String providerId, final String origin) {
        this.providerId = providerId;
        this.origin = origin;
    }
}
