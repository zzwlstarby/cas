package org.apereo.cas.util.junit;

/**
 * This is {@link RunningStandaloneCondition}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 * @deprecated Not needed with Junit5
 */
@Deprecated
public class RunningStandaloneCondition extends RunningContinuousIntegrationCondition {
    @Override
    public Boolean isSatisfied() {
        return !super.isSatisfied();
    }
}
