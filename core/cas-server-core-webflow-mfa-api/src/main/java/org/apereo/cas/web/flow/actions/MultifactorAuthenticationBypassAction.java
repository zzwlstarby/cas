package org.apereo.cas.web.flow.actions;

import org.apereo.cas.authentication.bypass.DefaultMultifactorAuthenticatonBypassResult;
import org.apereo.cas.web.flow.CasWebflowConstants;
import org.apereo.cas.web.support.WebUtils;

import lombok.extern.slf4j.Slf4j;
import lombok.val;

import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * Action that is responsible for determing if this MFA provider for the current subflow can
 * be bypassed for the user attempting to login into the service.
 *
 * @author Travis Schmidt
 * @since 5.3.4
 */
@Slf4j
public class MultifactorAuthenticationBypassAction extends AbstractMultifactorAuthenticationAction {

    @Override
    protected Event doExecute(final RequestContext requestContext) {
        val authentication = WebUtils.getAuthentication(requestContext);
        val service = WebUtils.getRegisteredService(requestContext);
        val request = WebUtils.getHttpServletRequestFromExternalWebflowContext();

        val bypass = provider.getBypassEvaluator();

        if (requestContext.getCurrentTransition().getId().equals(CasWebflowConstants.TRANSITION_ID_BYPASS)) {
            LOGGER.debug("Bypass triggered by MFA webflow for MFA for user [{}] for provider [{}]",
                    authentication.getPrincipal().getId(), provider.getId());
            bypass.setBypass(authentication, new DefaultMultifactorAuthenticatonBypassResult(provider.getId(), "WEBFLOW"));
            return yes();
        }

        val result = bypass.shouldExecute(authentication, service, provider, request);
        if (result) {
            LOGGER.debug("Bypass rules determined MFA should execute for user [{}] for provider [{}]",
                    authentication.getPrincipal().getId(), provider.getId());
            bypass.clearBypass(authentication);
            return no();
        }
        LOGGER.debug("Bypass rules determined MFA should NOT execute for user [{}] for provider [{}]",
                authentication.getPrincipal().getId(), provider.getId());
        return yes();
    }
}
