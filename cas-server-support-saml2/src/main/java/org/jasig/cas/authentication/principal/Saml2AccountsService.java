package org.jasig.cas.authentication.principal;

import org.jasig.cas.saml2.support.ServiceProviderConfig;
import org.jasig.cas.saml2.util.SAML2RequestReader;
import org.opensaml.saml2.core.AuthnRequest;

public class Saml2AccountsService extends AbstractWebApplicationService {

	private static final long			serialVersionUID	= -3827549250640938326L;

	// ----------------------------------------------------------------------------
	// Execution Variables
	private final ServiceProviderConfig	spConfig;

	private final String				relayState;

	private String						xmlSamlRequest;

	private transient AuthnRequest		authnRequest		= null;
	// ----------------------------------------------------------------------------

	public Saml2AccountsService(final String pAssertionConsumerServiceUrl, final String pRelayState, final ServiceProviderConfig pSpConfig) {
		super(pAssertionConsumerServiceUrl, pAssertionConsumerServiceUrl, null, null);
		this.spConfig = pSpConfig;
		this.relayState = pRelayState;
	}

	@Override
	public Response getResponse(final String ticketId) {
		return this.getSpConfig().getResponse(getPrincipal(), this.getAuthnRequest(), this.getRelayState());
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
	 * @return the spConfig
	 */
	public ServiceProviderConfig getSpConfig() {
		return spConfig;
	}

	/**
	 * @return the relayState
	 */
	public String getRelayState() {
		return relayState;
	}

	/**
	 * @return the authnRequest
	 */
	public AuthnRequest getAuthnRequest() {
		if (this.authnRequest == null) {
			this.authnRequest = SAML2RequestReader.getAuthnRequest(this.xmlSamlRequest);
		}
		return this.authnRequest;
	}
}
