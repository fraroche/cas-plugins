package org.jasig.cas.web.support;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import org.jasig.cas.authentication.principal.Saml2AccountsService;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.saml2.support.ServiceProvider;
import org.jasig.cas.saml2.util.SAML2RequestReader;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Saml2AccountsArgumentExtractor extends AbstractSingleSignOutEnabledArgumentExtractor {

	private static final Logger			LOGGER				= LoggerFactory.getLogger(Saml2AccountsArgumentExtractor.class);

	public static final String			CONST_PARAM_SERVICE	= "SAMLRequest";

	public static final String			CONST_RELAY_STATE	= "RelayState";

	@NotNull
	@Size(min = 1)
	private List<ServiceProvider>	serviceProviderConfig;

	@Override
	protected WebApplicationService extractServiceInternal(final HttpServletRequest pRequest) {
		LOGGER.trace("> extractServiceInternal()");

		// keep a trace of the relay state value to be able, according to WebSSO SAML 2 profile, to post it back in the
		// response
		final String lRelayState = pRequest.getParameter(Saml2AccountsArgumentExtractor.CONST_RELAY_STATE);
		final String lXmlRequest = SAML2RequestReader.decodeXMLAuthnRequest(pRequest.getParameter(Saml2AccountsArgumentExtractor.CONST_PARAM_SERVICE));
		AuthnRequest lAuthnRequest = null;
		Issuer lIssuer = null;
		ServiceProvider lSpConfig = null;
		String lAssertionConsumerServiceUrl = null;
		WebApplicationService lService = null;
		
//		if (lXmlRequest != null && lXmlRequest.length() != 0 
//				&& (lAuthnRequest = SAML2RequestReader.getAuthnRequest(lXmlRequest)) != null 
//				&& (lIssuer = lAuthnRequest.getIssuer()) != null
//				&& (lSpConfig = this.findAppropriateSpConfig(lIssuer)) != null) {
//			lAssertionConsumerServiceUrl = lAuthnRequest.getAssertionConsumerServiceURL();
//			lService = new Saml2AccountsService(lAssertionConsumerServiceUrl, lRelayState, lSpConfig);
//		}
		
		if (lXmlRequest != null && lXmlRequest.length() != 0) {
			lAuthnRequest = SAML2RequestReader.getAuthnRequest(lXmlRequest);
			if (lAuthnRequest != null) {
				lIssuer = lAuthnRequest.getIssuer();
				if (lIssuer != null) {
					lSpConfig = this.findAppropriateSpConfig(lIssuer);
					if (lSpConfig != null) {
						lAssertionConsumerServiceUrl = lAuthnRequest.getAssertionConsumerServiceURL();
						lService = new Saml2AccountsService(lAssertionConsumerServiceUrl, lRelayState, lSpConfig);
					}
				}
			}
		}

		LOGGER.trace("< extractServiceInternal()");
		return lService;
	}

	private ServiceProvider findAppropriateSpConfig(final Issuer pIssuer) {
		LOGGER.trace("> findAppropriateSpConfig()");

		for (ServiceProvider lSpConfig : this.serviceProviderConfig) {
			if (lSpConfig.isAppropriateServiceProvider(pIssuer)) {
				LOGGER.trace("< findAppropriateSpConfig()");
				return lSpConfig;
			}
		}

		LOGGER.trace("< findAppropriateSpConfig()");
		return null;
	}

	/**
	 * @param pServiceProviderConfig
	 *            the serviceProviderConfig to set
	 */
	public void setServiceProviderConfig(List<ServiceProvider> pServiceProviderConfig) {
		serviceProviderConfig = pServiceProviderConfig;
	}
}
