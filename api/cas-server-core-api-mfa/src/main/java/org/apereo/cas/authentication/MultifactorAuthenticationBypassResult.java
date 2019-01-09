package org.apereo.cas.authentication;

import java.time.ZonedDateTime;

/**
 *API Interface for Multifactor Authentication Bypass.
 *
 * @author Travis Schmidt
 * @since 6.0
 */
public interface MultifactorAuthenticationBypassResult {

    /**
     * The ID of the MFA Provider that is bypassed.
     *
     * @return - the id
     */
    String getProviderId();

    /**
     * The origin of the bypass provider.
     *
     * @return - the origin
     */
    String getOrigin();

    /**
     * The time the bypass was set.
     *
     * @return - ZonedDatetime
     */
    ZonedDateTime getBypassSetAt();

    /**
     * The time the bypass expires.
     *
     * @return - ZonedDateTime
     */
    ZonedDateTime getBypassExpiresAt();
}
