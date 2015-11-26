package org.jasig.cas.authentication.principal;

import java.io.IOException;
import java.io.ObjectInputStream;

import javax.validation.constraints.NotNull;

import org.jasig.cas.saml2.support.ServiceProvider;
import org.jasig.cas.saml2.util.SAML2RequestReader;
import org.opensaml.saml2.core.AuthnRequest;

public class Saml2AccountsService extends AbstractWebApplicationService {

	private static final long			serialVersionUID	= -3827549250640938326L;

	// ----------------------------------------------------------------------------
	// Execution Variables
	private final ServiceProvider	serviceProvider;

	private final String			relayState;

	@NotNull
	private final String			xmlSamlRequest;

	@NotNull
	private transient AuthnRequest	authnRequest;
	// ----------------------------------------------------------------------------

	public Saml2AccountsService(final String pAssertionConsumerServiceUrl, final String pRelayState, final String pXmlSamlRequest, final ServiceProvider pServiceProvider) {
		super(pAssertionConsumerServiceUrl, pAssertionConsumerServiceUrl, null, null);
		this.serviceProvider = pServiceProvider;
		this.relayState = pRelayState;
		this.xmlSamlRequest = pXmlSamlRequest;
		this.authnRequest = SAML2RequestReader.getAuthnRequest(pXmlSamlRequest);
	}

	@Override
	public Response getResponse(final String ticketId) {
		return this.getServiceProvider().getResponse(getPrincipal(), this.authnRequest, this.relayState);
	}

	/**
	 * Service does not support Single Log Out
	 * 
	 * @see org.jasig.cas.authentication.principal.WebApplicationService#logOutOfService(java.lang.String)
	 */
	@Override
	public boolean logOutOfService(final String pSessionIdentifier) {
		return false;
	}

	/**
	 * @return the serviceProvider
	 */
	public ServiceProvider getServiceProvider() {
		return serviceProvider;
	}

	/**
	 * @return the relayState
	 */
	public String getRelayState() {
		return relayState;
	}

	private void readObject(final ObjectInputStream pObjInputStream) throws IOException, ClassNotFoundException {
		pObjInputStream.defaultReadObject();
		this.authnRequest = SAML2RequestReader.getAuthnRequest(this.xmlSamlRequest);
	}
}
