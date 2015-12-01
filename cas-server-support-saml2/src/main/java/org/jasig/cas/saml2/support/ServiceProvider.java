package org.jasig.cas.saml2.support;

import java.io.ObjectStreamException;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.validation.constraints.NotNull;

import org.apache.commons.codec.binary.Base64;
import org.jasig.cas.authentication.principal.Principal;
import org.jasig.cas.saml2.util.SAML2ResponseBuilder;
import org.jasig.cas.web.support.Saml2AccountsArgumentExtractor;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServiceProvider implements Serializable {

	private static final long				serialVersionUID					= -2339718197074244232L;

	private static final Logger				LOGGER								= LoggerFactory.getLogger(ServiceProvider.class);

	/**
	 * This constant is to be used in Spring configuration XML file when you need to reference a Saml Attribute value.<br>
	 * ex:
	 * 
	 * <pre>
	 * {@code
	 * <property name="attributeList">
	 * 	<util:list>
	 * 		<util:list>
	 * 			<value>urn:oid:1.2.840.113556.1.4.221</value>
	 * 			<value>urn:oasis:names:tc:SAML:2.0:attrname-format:uri</value>
	 * 			<util:constant static-field="org.jasig.cas.saml2.support.ServiceProvider.USER_ID"/>
	 * 		</util:list>
	 * 	</util:list>
	 * </property>
	 * }
	 * </pre>
	 * <ul>
	 * <li>USER_ID references the CAS Principal.id if "<tt>alternateUserName</tt>" is not set</li>
	 * <li>if "<tt>alternateUserName</tt>
	 * " is set, USER_ID references the CAS Principal.attribute referenced by the value of "<tt>alternateUserName</tt>"</li>
	 * </ul>
	 */
	public static final String	USER_ID								= "UserId";

	// ----------------------------------------------------------------------------
	// Configuration Variables

	/**
	 * Url of the SP MetaDatas Provider.
	 */
	private String						spMetaDataProviderUrl;

	/**
	 * XML value of the SP MetaData.
	 */
	/*
	 * TODO RG_3_0
	 * If the spMetaDataProviderUrl is not null,
	 * then try to fetch the meta data XML and initialize 'spMetaDataXML'.
	 * After that, set spMetaDataProviderUrl to null to be sure that fetching the SP meta data
	 * can only occur once per VM lifecycle.
	 */
	private String						spMetaDataXML;

	/**
	 * Parsed and unmarshalled form of the Service Provider XML meta data.
	 * Even though ServiceProvider is never really serialized because of the writeReplace mechanism,
	 * SPSSODescriptor must be transient to allow compilation since this class 
	 */
	/*
	 * TODO RG_4_0
	 * For performance considerations, parsing and unmarshalling should occur only one time per VM session.
	 * Once the spMetaData is set, to null if the unmarshaling failed, or to the umarshalled value, set the
	 * spMetaDataXML to null
	 * so that unmarshalling process occurs one time only.
	 */
	private transient SPSSODescriptor	spMetaData;

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

	/**
	 * Saml response consumer service url.
	 * <ul>
	 * <li>If the "assertionConsumerServiceUrlRequired" is set to "true", then the "assertionConsumerServiceUrl" is set
	 * from the corresponding value in the authentication request.<br>
	 * Not that if this field is not present in the request, an error must be produced</li>
	 * <li>If the "assertionConsumerServiceUrlRequired" is set to "false", then it could be either set in XML by
	 * configuration or find, if present, in the SP metadatas (cf. AssertionConsumerService/Location)</li>
	 * </ul>
	 */
	/*
	 * TODO RG_1_0 :
	 * If the "assertionConsumerServiceUrlRequired" is set to "true", then the "assertionConsumerServiceUrl"
	 * is set from the corresponding value in the authentication request.
	 */
	private String getAssertionConsumerServiceUrlToUse(final AuthnRequest pSamlRequest) {
		// RG_1_0
		LOGGER.trace("> getAssertionConsumerServiceUrlToUse");

		String lAssertionConsumerServiceUrl = this.assertionConsumerServiceUrl;
		if (this.assertionConsumerServiceUrlRequired) {
			lAssertionConsumerServiceUrl = pSamlRequest.getAssertionConsumerServiceURL();
		}
		LOGGER.trace("< getAssertionConsumerServiceUrlToUse");
		return lAssertionConsumerServiceUrl;
	}

	/*
	 * TODO RG_1_1 :
	 * If this field is not present in the request, an error must be produced
	 */
	/**
	 * Validate that the assertionConsumerServiceUrl is present if this value is mandatory
	 * 
	 * @param pSamlRequest
	 * @return true if assertionConsumerServiceUrl is not mandatory or if the assertionConsumerServiceUrl is present in
	 *         the SAML Request
	 */
	private boolean raiseErrorOnAssertionConsumerServiceUrlControl(final AuthnRequest pSamlRequest) {
		// RG_1_1
		LOGGER.trace("> raiseErrorOnAssertionConsumerServiceUrlControl");

		boolean lRaiseError = true;
		if (!this.assertionConsumerServiceUrlRequired || (pSamlRequest != null && !pSamlRequest.getAssertionConsumerServiceURL().isEmpty())) {
			lRaiseError = false;
		}

		LOGGER.trace("< raiseErrorOnAssertionConsumerServiceUrlControl");
		return lRaiseError;
	}
	/*
	 * TODO RG_1_2 :
	 * If the "assertionConsumerServiceUrlRequired" is set to "false", then it could be either set in XML by
	 * configuration or find, if present, in the SP metadatas
	 */
	private String				assertionConsumerServiceUrl;

	/**
	 * Format of the "Response/Assertion/Subject/NameID" of the SAML response.<br>
	 * Ex: saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"<br>
	 * The "NameIDFormat" of the SP metadata. If not present in the SP metadata, the responsability of setting this
	 * value remains to the IdP: this value can be field by XML configuration.
	 */
	/*
	 * TODO RG_2_0:
	 * If "nameIdFormat" is null, then check in the SP metadatas if the "NameIDFormat" is present.
	 * If present, initialize "nameIdFormat" with it's value
	 */
	private String				nameIdFormat;

	/**
	 * Allow to replace the SAML response Subject/NameID obtained from the "Principal.getId()" by the value of any
	 * attribute present in this Principal.
	 */
	private String				alternateUserName;

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

	@NotNull
	private X509Certificate					x509certificate;

	@NotNull
	private PrivateKey						privateKey;

	/**
	 * add the <Conditions> to the SAML <Assertion>
	 */
	private ArrayList<URI>					restrictedURIs;

	/**
	 * The attributeList maps "AttributeStatement.Attribute Name" of the SAML Response to the "Principal.Attribute"
	 * The list must be formated as follow: (<[SamlAttributName[mandatory]], [SamlAttributeNameFormat[optional]],
	 * [CasPrincipalAttributeName[mandatory]]>)*
	 * ex:
	 * 
	 * <pre>
	 * {@code
	 * <property name="attributeList">
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
	private ArrayList<ArrayList<String>>	attributeList;

	// End of configuration Variables
	// ----------------------------------------------------------------------------
	

	public boolean isAppropriateServiceProvider(@NotNull
	final String pIssuerUrl) {
		LOGGER.trace("> isAppropriateServiceProvider()");
	
		URL lIssuerUrl = null;
		boolean lMatchingServiceProvider = false;
		if (pIssuerUrl.equals(this.spIssuerUrl)) {
			lMatchingServiceProvider = true;
		} else {
			try {
				lIssuerUrl = new URL(pIssuerUrl);
				if (this.spIssuerUrl.indexOf(lIssuerUrl.getHost()) != -1) {
					lMatchingServiceProvider = true;
				}
			} catch (MalformedURLException e) {
				LOGGER.error("Error while parsing the '" + pIssuerUrl + "' string in URL.", e);
			}
		}
	
		LOGGER.trace("< isAppropriateServiceProvider()");
		return lMatchingServiceProvider;
	}

	public org.jasig.cas.authentication.principal.Response getResponse(final Principal pCasPrincipal, final AuthnRequest pAuthnRequest, final String pRelayState) {
		LOGGER.trace("> getResponse()");

		final Map<String, String> lParameters = new HashMap<String, String>();
		final Response lSamlResponse = buildSamlResponse(pCasPrincipal, pAuthnRequest);
		String lXmlResponse = null;

		String lSignedResponse = null;
		try {
			lXmlResponse = SAML2ResponseBuilder.marshallAndSerialize(lSamlResponse);
			if (this.samlResponseBase64encoded) {
				lXmlResponse = Base64.encodeBase64String(lXmlResponse.getBytes());
			}

			lSignedResponse = lXmlResponse;
			lParameters.put("SAMLResponse", lSignedResponse);
			lParameters.put("RelayState", pRelayState);
		} catch (MarshallingException e) {
			LOGGER.error("Error while marshalling samlResponse.", e);
		}

		org.jasig.cas.authentication.principal.Response lResponse = org.jasig.cas.authentication.principal.Response.getPostResponse(pAuthnRequest.getAssertionConsumerServiceURL(), lParameters);

		LOGGER.trace("< getResponse()");
		return lResponse;
	}

	private Response buildSamlResponse(final Principal pCasPrincipal, final AuthnRequest pAuthnRequest) {
		LOGGER.trace("> buildSamlResponse()");

		String lAssertionConsumerServiceUrl = null;

		final String lUserId = getUserId(pCasPrincipal);

		Response lResponse = SAML2ResponseBuilder.buildResponseEnveloppe(null);

		lResponse.setInResponseTo(pAuthnRequest.getID());

		// add the <Issuer> to the SAML <Response>
		SAML2ResponseBuilder.addResponseIssuer(lResponse, this.idpIssuerUrl);
		SAML2ResponseBuilder.addStatus(lResponse, StatusCode.SUCCESS_URI);

		// add <Assertion>
		Assertion lAssertion = buildSamlAssertion(pCasPrincipal, pAuthnRequest, lUserId, lResponse, lAssertionConsumerServiceUrl);
		lResponse.getAssertions().add(lAssertion);

		lResponse.setDestination(lAssertionConsumerServiceUrl);

		LOGGER.trace("< buildSamlResponse()");
		return lResponse;
	}

	private Assertion buildSamlAssertion(final Principal pCasPrincipal, final AuthnRequest pAuthnRequest, final String pUserId, final Response pResponse, final String pAssertionConsumerServiceUrl) {
		LOGGER.trace("> buildSamlAssertion()");

		Assertion lAssertion = SAML2ResponseBuilder.buildAssertion(pResponse);
		DateTime lDebutValidite = pResponse.getIssueInstant();
		DateTime lFinValidite = pResponse.getIssueInstant().plusDays(30);

		// add the <Issuer> to the SAML <Assertion>
		SAML2ResponseBuilder.addAssertionIssuer(lAssertion, this.idpIssuerUrl);

		// add the <Signature> to the SAML <Assertion>
		BasicX509Credential lCredential = null;
		lCredential = new BasicX509Credential();
		lCredential.setEntityCertificate(this.x509certificate);
		lCredential.setPrivateKey(this.privateKey);
		Signature lAssertionSignature = SAML2ResponseBuilder.attachSignatureToSignableSAMLObject(lAssertion, lCredential);

		// add the <Subject> to the SAML <Assertion>
		String lInResponseTo = pAuthnRequest.getID();
		URI lRecipient = null;
		if (pAssertionConsumerServiceUrl != null) {
			try {
				lRecipient = new URI(pAssertionConsumerServiceUrl);
			} catch (URISyntaxException e) {
				LOGGER.error("Error while creating URI instance from '" + pAssertionConsumerServiceUrl + "'", e);
			}
		}
		SAML2ResponseBuilder.addSubject(lAssertion, pUserId, lDebutValidite, lFinValidite, lInResponseTo, lRecipient);

		// add the <Conditions> to the SAML <Assertion>
		SAML2ResponseBuilder.addConditions(lAssertion, lDebutValidite, lFinValidite, this.restrictedURIs);

		// add the <AttributeStatement> to the SAML <Assertion>
		AttributeStatement lAttStat = null;
		for (List<String> lList : attributeList) {
			lAttStat = addAttributeToAttributeStatement(pCasPrincipal, lAttStat, lList);
		}
		SAML2ResponseBuilder.addAttributeStatement(lAssertion, lAttStat);

		// add the <AuthnStatement> to the SAML <Assertion>
		SAML2ResponseBuilder.addAuthnStatement(lAssertion, lDebutValidite, lFinValidite, null, null);

		// Marshall the Object Tree
		try {
			Configuration.getMarshallerFactory().getMarshaller(lAssertion).marshall(lAssertion);
		} catch (MarshallingException e) {
			LOGGER.error("Unable to marshal Object Tree", e);
		}

		// Computing the Signature Value
		try {
			Signer.signObject(lAssertionSignature);
		} catch (SignatureException e) {
			LOGGER.error("Unable to compute signature", e);
		}

		LOGGER.trace("< buildSamlAssertion()");
		return lAssertion;
	}

	private AttributeStatement addAttributeToAttributeStatement(final Principal pCasPrincipal, final AttributeStatement pAttStat, final List<String> pList) {
		LOGGER.trace("> addAttributeToAttributeStatement()");

		AttributeStatement lAttStat = null;
		String lSamlAttributeName = null;
		String lSamlAttributeFormatName = null;
		String lCasPrincipalAttributeName = null;
		String lSamlAttributeValue = null;

		// check attribute list definition
		String lErrorString = "Wrong attribute list definition. the list must be formated as follow: <[SamlAttributName[mandatory]], [SamlAttributeNameFormat[optional]], [CasPrincipalAttributeName[mandatory]]>";
		if (pList.size() > 3) {
			LOGGER.error(lErrorString);
			return pAttStat;
		}
		if (pList.size() == 3) {
			lSamlAttributeFormatName = pList.get(1);
			if (lSamlAttributeFormatName == null || lSamlAttributeFormatName.indexOf("urn:oasis:names:tc:SAML:2.0:attrname-format:") == -1) {
				LOGGER.error(lErrorString);
				return pAttStat;
			}
			lCasPrincipalAttributeName = pList.get(2);
		} else {
			lCasPrincipalAttributeName = pList.get(1);
		}
		lSamlAttributeName = pList.get(0);
		// --

		if (USER_ID.equals(lCasPrincipalAttributeName)) {
			lSamlAttributeValue = getUserId(pCasPrincipal);
		} else {
			lSamlAttributeValue = getPrincipalAttribute(pCasPrincipal, lCasPrincipalAttributeName);
		}
		lAttStat = SAML2ResponseBuilder.addAttributeToAttributeStatement(pAttStat, lSamlAttributeName, lSamlAttributeFormatName, null, lSamlAttributeValue);

		LOGGER.trace("< addAttributeToAttributeStatement()");
		return lAttStat;
	}

	private String getUserId(final Principal pCasPrincipal) {
		LOGGER.trace("> getUserId()");

		final String lUserId;
		if (this.alternateUserName == null) {
			lUserId = pCasPrincipal.getId();
		} else {
			final String lAttributeValue = (String) pCasPrincipal.getAttributes().get(this.alternateUserName);
			if (lAttributeValue == null) {
				lUserId = pCasPrincipal.getId();
			} else {
				lUserId = lAttributeValue;
			}
		}

		LOGGER.trace("< getUserId()");
		return lUserId;
	}

	private String getPrincipalAttribute(final Principal pCasPrincipal, final String pPrincipalAttributeName) {
		LOGGER.trace("> getPrincipalAttribute()");

		String lAttributeValue = (String) pCasPrincipal.getAttributes().get(pPrincipalAttributeName);

		LOGGER.trace("< getPrincipalAttribute()");
		return lAttributeValue;
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
	 * @param pSpMetaDataProviderUrl the spMetaDataProviderUrl to set
	 */
	public void setSpMetaDataProviderUrl(final String pSpMetaDataProviderUrl) {
		this.spMetaDataProviderUrl = pSpMetaDataProviderUrl;
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
	 * @param pAlternateUserName
	 *            the alternateUserName to set
	 */
	public void setAlternateUserName(final String pAlternateUserName) {
		this.alternateUserName = pAlternateUserName;
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
	 * @param pX509certificate the x509certificate to set
	 */
	public void setX509certificate(final X509Certificate pX509certificate) {
		this.x509certificate = pX509certificate;
	}

	/**
	 * @param pPrivateKey the privateKey to set
	 */
	public void setPrivateKey(final PrivateKey pPrivateKey) {
		this.privateKey = pPrivateKey;
	}

	/**
	 * @param pRestrictedURIs the restrictedURIs to set
	 */
	public void setRestrictedURIs(final ArrayList<URI> pRestrictedURIs) {
		this.restrictedURIs = pRestrictedURIs;
	}

	/**
	 * @param pAttributeList the attributeList to set
	 */
	public void setAttributeList(final ArrayList<ArrayList<String>> pAttributeList) {
		this.attributeList = pAttributeList;
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
	private class SerializedForm implements Serializable {
		private final String	spIssuerUrl;

		private SerializedForm(final ServiceProvider pServiceProvider) {
			this.spIssuerUrl = pServiceProvider.spIssuerUrl;
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
}
