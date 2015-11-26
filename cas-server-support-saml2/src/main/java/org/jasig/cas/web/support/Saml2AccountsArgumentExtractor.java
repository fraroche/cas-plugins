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

	public static Saml2AccountsArgumentExtractor	instance			= null;

	public Saml2AccountsArgumentExtractor() {
		instance = this;
	}

	@NotNull
	@Size(min = 1)
	private List<ServiceProvider>	serviceProviderList;

	@Override
	protected WebApplicationService extractServiceInternal(final HttpServletRequest pRequest) {
		LOGGER.trace("> extractServiceInternal()");

		// keep a trace of the relay state value to be able, according to WebSSO SAML 2 profile, to post it back in the
		// response
		final String lRelayState = pRequest.getParameter(Saml2AccountsArgumentExtractor.CONST_RELAY_STATE);
		final String lXmlRequest = SAML2RequestReader.decodeXMLAuthnRequest(pRequest.getParameter(Saml2AccountsArgumentExtractor.CONST_PARAM_SERVICE));
		AuthnRequest lAuthnRequest = null;
		Issuer lIssuer = null;
		ServiceProvider lServiceProvider = null;
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
					String lIssuerURL = lIssuer.getValue();
					lServiceProvider = this.findAppropriateServiceProvider(lIssuerURL);
					if (lServiceProvider != null) {
						lAssertionConsumerServiceUrl = lAuthnRequest.getAssertionConsumerServiceURL();
						lService = new Saml2AccountsService(lAssertionConsumerServiceUrl, lRelayState, lXmlRequest, lServiceProvider);
					}
				}
			}
		}

		LOGGER.trace("< extractServiceInternal()");
		return lService;
	}

	public ServiceProvider findAppropriateServiceProvider(final String lIssuerURL) {
		LOGGER.trace("> findAppropriateServiceProvider()");

		for (ServiceProvider lSpConfig : this.serviceProviderList) {
			if (lSpConfig.isAppropriateServiceProvider(lIssuerURL)) {
				LOGGER.trace("< findAppropriateServiceProvider()");
				return lSpConfig;
			}
		}

		LOGGER.trace("< findAppropriateServiceProvider()");
		return null;
	}

	/**
	 * @param pServiceProviderList
	 *            the serviceProviderList to set
	 */
	public void setServiceProviderList(List<ServiceProvider> pServiceProviderList) {
		serviceProviderList = pServiceProviderList;
	}
}
