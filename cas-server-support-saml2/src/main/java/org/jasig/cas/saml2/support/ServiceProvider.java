package org.jasig.cas.saml2.support;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.saml2.flow.exception.ServiceProviderParamsException;
import org.jasig.cas.saml2.util.SAML2ResponseBuilder;
import org.jasig.cas.web.support.Saml2AccountsArgumentExtractor;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServiceProvider implements Serializable {
	private static final long					serialVersionUID					= -2339718197074244232L;

	private static final Logger					LOGGER								= LoggerFactory.getLogger(ServiceProvider.class);

	private static final SamlResponseBuilder	DEFAULT_RESPONSE_BUILDER			= new SamlResponseBuilderImpl();

	// static {
	// try {
	// // Initialize the library
	// OpenSamlBootstrap.bootstrap();
	// } catch (ConfigurationException e) {
	// LOGGER.error("Error in initializing the OpenSAML library, loading default configurations.", e);
	// }
	// }
	//
	// public ServiceProvider(final String pSpMetaDataProviderUrl) {
	// this.spMetaDataProviderUrl = pSpMetaDataProviderUrl;
	// this.spMetaDataXML = this.fetchSpMetaDataXML();
	// this.spMetaData = this.parseAndUnmarshall();
	// // TODO check Signature MetaData
	// this.exploitSpMetaData();
	// }



	// ----------------------------------------------------------------------------
	// Configuration Variables

	// /**
	// * Url of the SP MetaDatas Provider.
	// */
	// private String spMetaDataProviderUrl;
	//
	// /**
	// * XML value of the SP MetaData.
	// */
	// /*
	// * RG_3_0
	// * If the spMetaDataProviderUrl is not null,
	// * then try to fetch the meta data XML and initialize 'spMetaDataXML'.
	// * After that, set spMetaDataProviderUrl to null to be sure that fetching the SP meta data
	// * can only occur once per VM lifecycle.
	// */
	// private String spMetaDataXML = null;
	//
	// private String fetchSpMetaDataXML() {
	// LOGGER.trace("> fetchSpMetaDataXML(");
	//
	// // RG 3_0
	// String lSpMetaDataXML = null;
	// if (this.spMetaDataProviderUrl != null) {
	// try {
	// lSpMetaDataXML =
	// Request.Get(this.spMetaDataProviderUrl).connectTimeout(1000).socketTimeout(1000).execute().returnContent().asString();
	// } catch (ClientProtocolException e) {
	// LOGGER.error("Error while trying to fetch Service Provider Meta Data from url '" + this.spMetaDataProviderUrl +
	// "'", e);
	// } catch (IOException e) {
	// LOGGER.error("Error while trying to fetch Service Provider Meta Data from url '" + this.spMetaDataProviderUrl +
	// "'", e);
	// }
	// }
	// this.spMetaDataProviderUrl = null;
	//
	// LOGGER.trace("< fetchSpMetaDataXML(");
	// return lSpMetaDataXML;
	// }
	//
	// /**
	// * Parsed and unmarshalled form of the Service Provider XML meta data.
	// * Even though ServiceProvider is never really serialized because of the writeReplace mechanism,
	// * SPSSODescriptor must be transient to allow compilation since this class
	// */
	// /*
	// * RG_4_0
	// * For performance considerations, parsing and unmarshalling should occur only one time per VM session.
	// * Once the spMetaData is set, to null if the unmarshaling failed, or to the umarshalled value, set the
	// * spMetaDataXML to null
	// * so that unmarshalling process occurs one time only.
	// */
	// private transient SPSSODescriptor spMetaData;
	//
	// private SPSSODescriptor parseAndUnmarshall() {
	// // RG_4_0
	// LOGGER.trace("> parseAndUnmarshall()");
	//
	// SPSSODescriptor lSpSsoDescriptor = null;
	//
	// if (this.spMetaDataXML != null && !this.spMetaDataXML.isEmpty()) {
	// try {
	// Document spMetaDataDom = SAML2RequestReader.parseXML(this.spMetaDataXML);
	// EntityDescriptor lEntityDescriptor = (EntityDescriptor) SAML2RequestReader.unmarshallDOM(spMetaDataDom);
	// // lEntityDescriptor.getSPSSODescriptor(supportedProtocol)
	// } catch (XMLParserException e) {
	// LOGGER.error("Error while parsing following XML '" + this.spMetaDataXML + "'", e);
	// } catch (UnmarshallingException e) {
	// LOGGER.error("Error while umarshalling following XML '" + this.spMetaDataXML + "'", e);
	// }
	// }
	// this.spMetaDataXML = null;
	//
	// LOGGER.trace("< parseAndUnmarshall()");
	// return lSpSsoDescriptor;
	// }
	//
	// protected SignatureTrustEngine getTrustEngine(MetadataProvider provider) {
	// Set<String> trustedKeys = null;
	// boolean verifyTrust = true;
	// boolean forceRevocationCheck = false;
	// if (provider instanceof ExtendedMetadataDelegate) {
	// ExtendedMetadataDelegate metadata = (ExtendedMetadataDelegate) provider;
	// trustedKeys = metadata.getMetadataTrustedKeys();
	// verifyTrust = metadata.isMetadataTrustCheck();
	// forceRevocationCheck = metadata.isForceMetadataRevocationCheck();
	// }
	// if (verifyTrust) {
	// LOGGER.debug("Setting trust verification for metadata provider {}", provider);
	// CertPathPKIXValidationOptions pkixOptions = new CertPathPKIXValidationOptions();
	// if (forceRevocationCheck) {
	// LOGGER.debug("Revocation checking forced to true");
	// pkixOptions.setForceRevocationEnabled(true);
	// } else {
	// LOGGER.debug("Revocation checking not forced");
	// pkixOptions.setForceRevocationEnabled(false);
	// }
	// return new PKIXSignatureTrustEngine(getPKIXResolver(provider, trustedKeys, null),
	// Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver(),
	// new CertPathPKIXTrustEvaluator(pkixOptions), new BasicX509CredentialNameEvaluator());
	// } else {
	// LOGGER.debug("Trust verification skipped for metadata provider {}", provider);
	// return new
	// AllowAllSignatureTrustEngine(Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver());
	// }
	// }
	//
	// private SPSSODescriptor fetchSpMetaData() {
	// LOGGER.trace("> fetchSpMetaData()");
	//
	// SPSSODescriptor lSpSsoDescriptor = null;
	// try {
	// HTTPMetadataProvider lHttpMetadataProvider = new HTTPMetadataProvider(new Timer(true), new HttpClient(),
	// this.spIssuerUrl);
	// lHttpMetadataProvider.setRefreshDelayFactor(1);
	// lHttpMetadataProvider.setParserPool(Configuration.getParserPool());
	// lHttpMetadataProvider.setMetadataFilter(new SignatureValidationFilter(new SignatureTrustEngine() {
	//
	// @Override
	// public boolean validate(Signature pToken, CriteriaSet pTrustBasisCriteria) throws SecurityException {
	// // TODO Auto-generated method stub
	// return false;
	// }
	//
	// @Override
	// public boolean validate(byte[] pSignature, byte[] pContent, String pAlgorithmURI, CriteriaSet
	// pTrustBasisCriteria, Credential pCandidateCredential) throws SecurityException {
	// // TODO Auto-generated method stub
	// return false;
	// }
	//
	// @Override
	// public KeyInfoCredentialResolver getKeyInfoResolver() {
	// // TODO Auto-generated method stub
	// return null;
	// }
	// }));
	// lHttpMetadataProvider.initialize();
	//
	// lHttpMetadataProvider.getMetadata();
	// } catch (MetadataProviderException e) {
	// }
	//
	//
	// LOGGER.trace("< fetchSpMetaData()");
	// return lSpSsoDescriptor;
	// }
	//
	// private void exploitSpMetaData() {
	// String lBindingType = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
	// if (this.spMetaData != null) {
	// for (AssertionConsumerService lAcs : this.spMetaData.getAssertionConsumerServices()) {
	// if (lBindingType.equals(lAcs.getBinding())) {
	// this.assertionConsumerServiceUrl = lAcs.getLocation();
	// break;
	// }
	// }
	// }
	// }
	/**
	 * Issuer of the authentication request. <br>
	 * It corresponds to the "EntityDescriptor/entityID" of the IdP metadatas.
	 */
	@NotNull
	private String				idpIssuerUrl;

	/**
	 * Issuer of the authentication request. <br>
	 * It corresponds to the "EntityDescriptor/entityID" of the SP metadatas.
	 * 
	 */
	@NotNull
	private String				spIssuerUrl;

	/**
	 * <ul>
	 * <li><tt>true</tt> if the "assertionConsumerServiceUrl" must be found in the authentication request.<br>
	 * </li>
	 * <li><tt>false</tt> otherwise</li>
	 * </ul>
	 * Set to <tt>false</tt> by default
	 */
	private boolean				assertionConsumerServiceUrlRequired	= false;

	/*
	 * RG_1_2 :
	 * If the "assertionConsumerServiceUrlRequired" is set to "false", use this variable,
	 * if set to "true", use the assertionConsumerServieUrl value from the SAML 2 authnRequest
	 */
	private String				assertionConsumerServiceUrl;

	/**
	 * Format of the "Response/Assertion/Subject/NameID" of the SAML response.<br>
	 * Ex: saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"<br>
	 * The "NameIDFormat" of the SP metadata. If not present in the SP metadata, the responsability of setting this
	 * value remains to the IdP: this value can be filled by XML configuration.
	 */
	/*
	 * TODO RG_2_0:
	 * If "nameIdFormat" is null, then check in the SP metadatas if the "NameIDFormat" is present.
	 * If present, initialize "nameIdFormat" with it's value
	 */
	private String				nameIdFormat;

	/**
	 * If this field is set to true, this means that the authentication request has been transformed by a "deflate"
	 * compression mechanism.<br>
	 * Default to "false"
	 */
	private boolean				activateDeflate						= false;

	/**
	 * true if the SAML response must be base 64 encoded, false otherwise
	 * Default to "true"
	 */
	private boolean				samlResponseBase64encoded			= true;

	// /**
	// * Component in charge of producing the signature of the SAML Response
	// */
	// private Signer responseSigner;
	//
	// /**
	// * Component in charge of producing the signature of the SAML Assertion
	// */
	// private Signer assertionSigner;
	//
	// /**
	// * Component in charge of producing the SAML Response Ciphering
	// */
	// private Cipherer responseCipherer;


	/**
	 * The casTosaml2PrincipalMapper maps "AttributeStatement.Attribute Name" of the SAML Response to the "Principal.Attribute"
	 * The list must be formatted as follows : (<[SamlAttributName[mandatory]], [SamlAttributeNameFormat[optional]],
	 * [CasPrincipalAttributeName[mandatory]]>)*
	 * ex:
	 * 
	 * <pre>
	 * {@code
	 * <property name="casTosaml2PrincipalMapper">
	 * 	<util:list>
	 * 		<util:list>
	 * 			<value>urn:oid:1.2.840.113556.1.4.221</value>
	 * 			<value>urn:oasis:names:tc:SAML:2.0:attrname-format:uri</value>
	 * 			<util:constant static-field="fr.si2m.socle.security.auth.cas.authentication.principal.Saml2AccountsService.USER_ID"/>
	 * 		</util:list>
	 * 	</util:list>
	 * </property>
	 * }
	 * </pre>
	 */
	private CasToSaml2PrincipalMapper	casTosaml2PrincipalMapper;

	private SamlResponseBuilder			samlResponseBuilder					= ServiceProvider.DEFAULT_RESPONSE_BUILDER;
	public boolean isAppropriateServiceProvider(@NotNull
	final String pIssuerValue) {
		LOGGER.trace("> isAppropriateServiceProvider()");

		boolean lMatchingServiceProvider = false;
		if (pIssuerValue.equals(this.spIssuerUrl)) {
			lMatchingServiceProvider = true;
		} else {
			try {
				if ((this.spIssuerUrl.indexOf(pIssuerValue) != -1)
						|| ((this.spIssuerUrl.startsWith("http")) ? (pIssuerValue.indexOf(new URL(this.spIssuerUrl).getHost()) != -1) : (pIssuerValue.indexOf(this.spIssuerUrl) != -1))) {
					lMatchingServiceProvider = true;
				}
			} catch (MalformedURLException e) {
				LOGGER.error("Error while parsing the '" + pIssuerValue + "' string in URL.", e);
			}
		}
	
		LOGGER.trace("< isAppropriateServiceProvider()");
		return lMatchingServiceProvider;
	}

	public org.jasig.cas.authentication.principal.Response getResponse(final Principal pCasPrincipal, final AuthnRequest pAuthnRequest, final String pRelayState) {
		LOGGER.trace("> getResponse()");

		// RG_1_1
		if (errorOnAssertionConsumerServiceUrlControl(pAuthnRequest) && (this.assertionConsumerServiceUrl == null || this.assertionConsumerServiceUrl.isEmpty())) {
			String lMsgError = "No AssertionConsumerServiceUrl found in the Authentication Request wheras 'assertionConsumerServiceUrlRequired' flag is enabled.";
			LOGGER.error(lMsgError);
			throw new ServiceProviderParamsException(lMsgError);
		}
		final String lAssertionConsumerServiceUrl = getAssertionConsumerServiceUrlToUse(pAuthnRequest);

		final Map<String, String> lParameters = new HashMap<String, String>();
		final CasToSaml2Principal lSamlPrincipal = buildCasToSaml2Principal(pCasPrincipal);
		Response lSamlResponse = this.samlResponseBuilder.build(lSamlPrincipal, this.idpIssuerUrl, null, pAuthnRequest, lAssertionConsumerServiceUrl);

		String lXmlResponse = null;
		try {

			lXmlResponse = SAML2ResponseBuilder.marshallAndSerialize(lSamlResponse);

			if (this.activateDeflate) {
				byte[] lOutDeflated = SAML2ResponseBuilder.deflate(lXmlResponse);
				lXmlResponse = Base64.encodeBytes(lOutDeflated, Base64.DONT_BREAK_LINES);
			} else if (this.samlResponseBase64encoded) {
				lXmlResponse = Base64.encodeBytes(lXmlResponse.getBytes("UTF-8"), Base64.DONT_BREAK_LINES);
			}

			lParameters.put("SAMLResponse", lXmlResponse);
			lParameters.put("RelayState", pRelayState);
		} catch (MessageEncodingException e) {
			LOGGER.error("Error while marshalling samlResponse.", e);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("'UTF-8' encoding is not supported", e);
		}

		org.jasig.cas.authentication.principal.Response lResponse = org.jasig.cas.authentication.principal.Response.getPostResponse(lAssertionConsumerServiceUrl, lParameters);

		LOGGER.trace("< getResponse()");
		return lResponse;
	}

	/**
	 * Saml response consumer service url.
	 * <ul>
	 * <li>If the "assertionConsumerServiceUrlRequired" is set to "true", then the "assertionConsumerServiceUrl" is set
	 * from the corresponding value in the authentication request.<br>
	 * Note that if this field is not present in the request, an error must be produced</li>
	 * <li>If the "assertionConsumerServiceUrlRequired" is set to "false", then it could be either set in XML by
	 * configuration or found, if present, in the SP metadatas (cf. AssertionConsumerService/Location)</li>
	 * </ul>
	 */
	/*
	 * RG_1_0 :
	 * If the "assertionConsumerServiceUrlRequired" is set to "true", then the "assertionConsumerServiceUrl"
	 * is set from the corresponding value in the authentication request.
	 */
	private String getAssertionConsumerServiceUrlToUse(final AuthnRequest pSamlRequest) {
		// RG_1_0
		LOGGER.trace("> getAssertionConsumerServiceUrlToUse");
	
		// RG_1_2
		String lAssertionConsumerServiceUrl = this.assertionConsumerServiceUrl;
		if (this.assertionConsumerServiceUrlRequired || lAssertionConsumerServiceUrl == null) {
			lAssertionConsumerServiceUrl = pSamlRequest.getAssertionConsumerServiceURL();
		}
	
		LOGGER.trace("< getAssertionConsumerServiceUrlToUse");
		return lAssertionConsumerServiceUrl;
	}

	/*
	 * RG_1_1 :
	 * If this field is not present in the request, an error must be produced
	 */
	/**
	 * Validate that the assertionConsumerServiceUrl is present in the authentication request if this value is mandatory
	 * (i. e.
	 * assertionConsumerServiceUrlRequired = true)
	 * 
	 * @param pSamlRequest
	 * @return true if assertionConsumerServiceUrl is not mandatory or if the assertionConsumerServiceUrl is present in
	 *         the SAML Request
	 */
	private boolean errorOnAssertionConsumerServiceUrlControl(final AuthnRequest pSamlRequest) {
		// RG_1_1
		LOGGER.trace("> errorOnAssertionConsumerServiceUrlControl");
	
		boolean lError = false;
		if (this.assertionConsumerServiceUrlRequired && (pSamlRequest == null || pSamlRequest.getAssertionConsumerServiceURL().isEmpty())) {
			lError = true;
		}
	
		LOGGER.trace("< errorOnAssertionConsumerServiceUrlControl");
		return lError;
	}

	private CasToSaml2Principal buildCasToSaml2Principal(final Principal pCasPrincipal) {
		return new CasToSaml2Principal(pCasPrincipal, this.casTosaml2PrincipalMapper);
	}

	// ----------------------------------------------------------------------------
	
	// ----------------------------------------------------------------------------
	// SETTERS
	// ----------------------------------------------------------------------------
	/**
	 * @param pSpIssuerUrl
	 *            the spIssuerUrl to set
	 */
	public void setSpIssuerUrl(final String pSpIssuerUrl) {
		this.spIssuerUrl = pSpIssuerUrl;
	}

	/**
	 * @param pIdpIssuerUrl the idpIssuerUrl to set
	 */
	public void setIdpIssuerUrl(final String pIdpIssuerUrl) {
		this.idpIssuerUrl = pIdpIssuerUrl;
	}

	/**
	 * @param pAssertionConsumerServiceUrlPresence the assertionConsumerServiceUrlRequired to set
	 */
	public void setAssertionConsumerServiceUrlRequired(final boolean pAssertionConsumerServiceUrlPresence) {
		this.assertionConsumerServiceUrlRequired = pAssertionConsumerServiceUrlPresence;
	}

	/**
	 * @param pAssertionConsumerServiceUrl the assertionConsumerServiceUrl to set
	 */
	public void setAssertionConsumerServiceUrl(final String pAssertionConsumerServiceUrl) {
		this.assertionConsumerServiceUrl = pAssertionConsumerServiceUrl;
	}

	/**
	 * @param pNameIdFormat the nameIdFormat to set
	 */
	public void setNameIdFormat(final String pNameIdFormat) {
		this.nameIdFormat = pNameIdFormat;
	}

	/**
	 * @param pActivateDeflate the activateDeflate to set
	 */
	public void setActivateDeflate(final boolean pActivateDeflate) {
		this.activateDeflate = pActivateDeflate;
	}

	/**
	 * @param pSamlResponseBase64encoded the samlResponseBase64encoded to set
	 */
	public void setSamlResponseBase64encoded(final boolean pSamlResponseBase64encoded) {
		this.samlResponseBase64encoded = pSamlResponseBase64encoded;
	}

	/**
	 * @param pCas2samlAttributeMappingList
	 *            the casTosaml2PrincipalMapper to set
	 */
	public void setCasTosaml2PrincipalMapper(final CasToSaml2PrincipalMapper pCas2samlAttributeMappingList) {
		this.casTosaml2PrincipalMapper = pCas2samlAttributeMappingList;
	}

	// End of configuration Variables
	// ----------------------------------------------------------------------------

	/**
	 * @param pSamlResponseBuilder
	 *            the samlResponseBuilder to set
	 */
	public void setSamlResponseBuilder(SamlResponseBuilder pSamlResponseBuilder) {
		samlResponseBuilder = pSamlResponseBuilder;
	}

	/**
	 * This method is called by ObjectOutputStream to serialize a new instance of the SerializedForm class
	 * instead of the current ServiceProvider instance.
	 * 
	 * @return SerializedForm of the ServiceProvider class.
	 * @throws ObjectStreamException
	 */
	private Object writeReplace() throws ObjectStreamException {
		return new SerializedForm(this);
	}

	/**
	 * This class is a serialization replacement of the ServiceProvider class.
	 */
	private static class SerializedForm implements Serializable {
		/**
		 * 
		 */
		private static final long	serialVersionUID	= 1L;
		private final String	spIssuerUrl;

		private SerializedForm(final ServiceProvider pServiceProvider) {
			this.spIssuerUrl = pServiceProvider.spIssuerUrl;
			LOGGER.trace(this.spIssuerUrl);
		}

		/**
		 * This method is called by the ObjectOutputStream while de-serializing
		 * the SerializedForm of the ServiceProvider instance.
		 * It's aim is to find the appropriate ServiceProvider instance that matches the SerializedFrom spIssuerUrl
		 * 
		 * @return ServiceProvider instance
		 * @throws ObjectStreamException
		 */
		private Object readResolve() throws ObjectStreamException {
			return Saml2AccountsArgumentExtractor.instance.findAppropriateServiceProvider(this.spIssuerUrl);
		}
	}

	public static interface SamlResponseBuilder {
		public SamlAssertionBuilder getSamlAssertionBuilder();

		public Response build(final CasToSaml2Principal pSamlPrincipal, final String pIdpIssuerUrl, final Response pSamlResponse, final AuthnRequest pSamlRequest,
				final String pAssertionConsumerServiceUrl);
	}
	
	public static class SamlResponseBuilderImpl implements SamlResponseBuilder {
		private Credential				credential;

		private SamlAssertionBuilder	samlAssertionBuilder;


		public SamlResponseBuilderImpl() {
			super();
		}

		@Override
		public Response build(final CasToSaml2Principal pSamlPrincipal, final String pIdpIssuerUrl, final Response pSamlResponse, final AuthnRequest pSamlRequest,
				final String pAssertionConsumerServiceUrl) {
			LOGGER.trace("> build()");

			String lAssertionConsumerServiceUrl = pAssertionConsumerServiceUrl;

			final String lUserId = pSamlPrincipal.getId();

			Response lResponse = SAML2ResponseBuilder.buildResponseEnveloppe(null);

			lResponse.setInResponseTo(pSamlRequest.getID());

			// add the <Issuer> to the SAML <Response>
			SAML2ResponseBuilder.addResponseIssuer(lResponse, pIdpIssuerUrl);
			SAML2ResponseBuilder.addStatus(lResponse, StatusCode.SUCCESS_URI);

			lResponse.setDestination(lAssertionConsumerServiceUrl);

			// add <Assertion>
			Assertion lAssertion = getSamlAssertionBuilder().build(pSamlPrincipal, pIdpIssuerUrl, lResponse, pSamlRequest, lAssertionConsumerServiceUrl);

			lResponse.getAssertions().add(lAssertion);

			// add the <Signature> to the SAML <Response>
			Signature lResponseSignature = null;
			if (this.credential != null) {
				lResponseSignature = SAML2ResponseBuilder.attachSignatureToSignableSAMLObject(lResponse, this.credential);
			}

			// Marshall the Object Tree
			try {
				Configuration.getMarshallerFactory().getMarshaller(lResponse).marshall(lResponse);
			} catch (MarshallingException e) {
				LOGGER.error("Unable to marshal Object Tree", e);
			}

			// Computing the Signature Value don't forget to unmarshall the response before signing object
			// !_!!!!_!!!!_!_!_!!!!!!!!!!_!!!!_!!!!_!_!_!!!!!!!!!!_
			if (lResponseSignature != null) {
				try {
					Signer.signObject(lResponseSignature);
					LOGGER.debug("Signing ");
				} catch (SignatureException e) {
					LOGGER.error("Unable to compute signature", e);
				}
			}

			LOGGER.trace("< build()");
			return lResponse;
		}

		/**
		 * @param pCredential
		 *            the credential to set
		 */
		public void setCredential(final Credential pCredential) {
			credential = pCredential;
		}

		/**
		 * @return the samlAssertionBuilder
		 */
		public SamlAssertionBuilder getSamlAssertionBuilder() {
			return samlAssertionBuilder;
		}

		/**
		 * @param pSamlAssertionBuilder
		 *            the samlAssertionBuilder to set
		 */
		public void setSamlAssertionBuilder(SamlAssertionBuilder pSamlAssertionBuilder) {
			samlAssertionBuilder = pSamlAssertionBuilder;
		}

	}

	public static interface SamlAssertionBuilder {
		public Assertion build(final CasToSaml2Principal pSamlPrincipal, final String pIdpIssuerUrl, final Response pSamlResponse, final AuthnRequest pSamlRequest,
				final String pAssertionConsumerServiceUrl);
	}

	public static class SamlAssertionBuilderImpl implements SamlAssertionBuilder {

		private Credential		credential;

		/**
		 * add the <Conditions> to the SAML <Assertion>
		 */
		private ArrayList<URI>	restrictedURIs;

		private String			authnContextClassRef	= AuthnContext.UNSPECIFIED_AUTHN_CTX;

		private String			subjectNameIdFormat		= NameIDType.UNSPECIFIED;

		public SamlAssertionBuilderImpl() {
			super();
		}

		@Override
		public Assertion build(final CasToSaml2Principal pSamlPrincipal, final String pIdpIssuerUrl, final Response pSamlResponse, final AuthnRequest pSamlRequest,
				final String pAssertionConsumerServiceUrl) {
			LOGGER.trace("> build()");

			Assertion lAssertion = SAML2ResponseBuilder.buildAssertion(pSamlResponse);
			DateTime lDebutValidite = pSamlResponse.getIssueInstant();
			DateTime lFinValidite = pSamlResponse.getIssueInstant().plusDays(30);

			// add the <Issuer> to the SAML <Assertion>
			SAML2ResponseBuilder.addAssertionIssuer(lAssertion, pIdpIssuerUrl);

			// add the <Subject> to the SAML <Assertion>
			String lInResponseTo = pSamlRequest.getID();
			URI lRecipient = null;
			if (pAssertionConsumerServiceUrl != null) {
				try {
					lRecipient = new URI(pAssertionConsumerServiceUrl);
				} catch (URISyntaxException e) {
					LOGGER.error("Error while creating URI instance from '" + pAssertionConsumerServiceUrl + "'", e);
				}
			}
			SAML2ResponseBuilder.addSubject(lAssertion, pSamlPrincipal.getId(), lDebutValidite, lFinValidite, lInResponseTo, lRecipient, this.subjectNameIdFormat);

			// add the <Conditions> to the SAML <Assertion>
			SAML2ResponseBuilder.addConditions(lAssertion, lDebutValidite, lFinValidite, this.restrictedURIs);

			// add the <AttributeStatement> to the SAML <Assertion>
			AttributeStatement lAttStat = buildAttributeStatement(pSamlPrincipal);
			SAML2ResponseBuilder.addAttributeStatement(lAssertion, lAttStat);

			// add the <AuthnStatement> to the SAML <Assertion>
			SAML2ResponseBuilder.addAuthnStatement(lAssertion, lDebutValidite, lFinValidite, null, null, this.authnContextClassRef);


			// add the <Signature> to the SAML <Assertion>
			Signature lAssertionSignature = null;
			if (this.credential != null) {
				lAssertionSignature = SAML2ResponseBuilder.attachSignatureToSignableSAMLObject(lAssertion, this.credential);
			}

			// Marshall the Object Tree
			try {
				Configuration.getMarshallerFactory().getMarshaller(lAssertion).marshall(lAssertion);
			} catch (MarshallingException e) {
				LOGGER.error("Unable to marshal Object Tree", e);
			}

			// Computing the Signature Value
			if (lAssertionSignature != null) {
				try {
					Signer.signObject(lAssertionSignature);
				} catch (SignatureException e) {
					LOGGER.error("Unable to compute signature", e);
				}
			}


			LOGGER.trace("< build()");
			return lAssertion;
		}

		private AttributeStatement buildAttributeStatement(final CasToSaml2Principal pSamlPrincipal) {
			LOGGER.trace("> buildAttributeStatement()");

			AttributeStatement lAttStat = null;
			Map<String, Object> lCasToSamlAttributesMap = pSamlPrincipal.getAttributes();
			if (lCasToSamlAttributesMap != null) {
				Set<Entry<String, Object>> lCasToSamlAttributesSet = lCasToSamlAttributesMap.entrySet();
				for (Entry<String, Object> lEntry : lCasToSamlAttributesSet) {
					Attribute lSamlAttribute = (Attribute) lEntry.getValue();
					lAttStat = SAML2ResponseBuilder.addAttributeToAttributeStatement(lAttStat, lSamlAttribute);
				}
			}

			LOGGER.trace("< buildAttributeStatement()");
			return lAttStat;
		}

		/**
		 * @param pCredential
		 *            the credential to set
		 */
		public void setCredential(final Credential pCredential) {
			credential = pCredential;
		}

		/**
		 * @param pRestrictedURIs
		 *            the restrictedURIs to set
		 */
		public void setRestrictedURIs(final ArrayList<URI> pRestrictedURIs) {
			restrictedURIs = pRestrictedURIs;
		}

		/**
		 * @param pAuthnContextClassRef
		 *            the authnContextClassRef to set
		 */
		public void setAuthnContextClassRef(final String pAuthnContextClassRef) {
			authnContextClassRef = pAuthnContextClassRef;
		}

		/**
		 * @param pSubjectNameIdFormat
		 *            the subjectNameIdFormat to set
		 */
		public void setSubjectNameIdFormat(String pSubjectNameIdFormat) {
			subjectNameIdFormat = pSubjectNameIdFormat;
		}
	}

	public static class CasToSaml2Principal implements Principal {
		@NotNull
		private final Principal						casPrincipal;
		@NotNull
		private final CasToSaml2PrincipalMapper		casPrincipalMapper;

		public CasToSaml2Principal(final Principal pCasPrincipal, final CasToSaml2PrincipalMapper pCasPrincipalMapper) {
			this.casPrincipal = pCasPrincipal;
			this.casPrincipalMapper = pCasPrincipalMapper;
		}

		@Override
		public String getId() {
			LOGGER.trace("> getId()");

			String lUserId = this.casPrincipalMapper.getId(this.casPrincipal);

			LOGGER.trace("< getId()");
			return lUserId;
		}

		@Override
		public Map<String, Object> getAttributes() {
			LOGGER.trace("> getAttributes()");
			Map lOutAttributeMap = null;
			List<AttributeMapper> lMappingList = this.casPrincipalMapper.getAttributesMappingList();
			if (lMappingList != null && !lMappingList.isEmpty()) {
				lOutAttributeMap = new HashMap<String, Attribute>(lMappingList.size());
				for (AttributeMapper lAttributeMapper : lMappingList) {
					String lKey = lAttributeMapper.getMappedCasPrincipalAttributeName();
					Object lValue = lAttributeMapper.getSamlAttributeValue(this.casPrincipal);
					String lName = lAttributeMapper.getSamlAttributeName();
					String lNameFormat = lAttributeMapper.getSamlAttributeNameFormat();
					String lFriendlyName = lAttributeMapper.getSamlAttributeFriendlyName();

					Attribute lSamlAttribute = SAML2ResponseBuilder.buildAttribute(lName, lNameFormat, lFriendlyName, lValue);
					lOutAttributeMap.put(lKey, lSamlAttribute);
				}
			}
			LOGGER.trace("< getAttributes()");
			return lOutAttributeMap;
		}
	}
}
