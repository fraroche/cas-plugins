package org.jasig.cas.web.support;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.jasig.cas.authentication.principal.Saml2AccountsService;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.saml2.support.ServiceProviderConfig;
import org.jasig.cas.saml2.util.SAML2RequestReader;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;

public class Saml2AccountsArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {

	public static final String			CONST_PARAM_SERVICE	= "SAMLRequest";

	public static final String			CONST_RELAY_STATE	= "RelayState";

	@NotNull
	@Size(min = 1)
	private List<ServiceProviderConfig>	serviceProviderConfig;

	protected WebApplicationService extractServiceInternal(final HttpServletRequest pRequest) {
		// keep a trace of the relay state value to be able, according to WebSSO SAML 2 profile, to post it back in the
		// response
		final String lRelayState = pRequest.getParameter(Saml2AccountsArgumentExtractor.CONST_RELAY_STATE);
		final String lXmlRequest = SAML2RequestReader.decodeAuthnRequestXML(pRequest.getParameter(Saml2AccountsArgumentExtractor.CONST_PARAM_SERVICE));
		AuthnRequest lAuthnRequest = null;
		Issuer lIssuer = null;
		ServiceProviderConfig lSpConfig = null;
		String lAssertionConsumerServiceUrl = null;
		WebApplicationService lService = null;

		if (lXmlRequest != null && lXmlRequest.length() != 0) {
			if ((lAuthnRequest = SAML2RequestReader.getAuthnRequest(lXmlRequest)) != null) {
				if ((lIssuer = lAuthnRequest.getIssuer()) != null) {
					lSpConfig = this.findAppropriateSpConfig(lAuthnRequest, lIssuer);
					if (lSpConfig != null) {
						lAssertionConsumerServiceUrl = lAuthnRequest.getAssertionConsumerServiceURL();
						lService = new Saml2AccountsService(lAssertionConsumerServiceUrl, lRelayState, lSpConfig);
					}
				}
			}
		}
		return lService;
	}

	private ServiceProviderConfig findAppropriateSpConfig(final AuthnRequest pAuthnRequest, final Issuer pIssuer) {
		for (ServiceProviderConfig lSpConfig : this.serviceProviderConfig) {
			if (lSpConfig.isAppropriateSpConfig(pIssuer)) {
				return lSpConfig;
			}
		}
		return null;
	}

	/**
	 * @param pServiceProviderConfig
	 *            the serviceProviderConfig to set
	 */
	public void setServiceProviderConfig(List<ServiceProviderConfig> pServiceProviderConfig) {
		serviceProviderConfig = pServiceProviderConfig;
	}
}
