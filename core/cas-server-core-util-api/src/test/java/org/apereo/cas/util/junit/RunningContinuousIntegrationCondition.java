package org.apereo.cas.util.junit;

import lombok.val;

/**
 * This is {@link RunningContinuousIntegrationCondition}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 * @deprecated Not needed with Junit5
 */
@Deprecated
public class RunningContinuousIntegrationCondition implements IgnoreCondition {
    @Override
    public Boolean isSatisfied() {
        val sysProp = System.getProperty("CI", Boolean.FALSE.toString());
        val envProp = System.getenv("CI");
        return "true".equals(sysProp) || "true".equals(envProp);
    }
}
