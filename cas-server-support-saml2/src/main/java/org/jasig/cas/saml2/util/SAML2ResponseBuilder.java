package org.jasig.cas.saml2.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

import javax.validation.constraints.NotNull;
import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.OpenSamlBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.SubjectLocality;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.saml2.core.impl.SubjectLocalityBuilder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
/**
 * Working process principles :
 *
 *                                          |
 *                                          |
 *                                        Build
 *                                          |
 *                                          |
 *                                          V
 *	XML --Parse--> DOM --Unmarshall--> Java Objects --Marshall--> DOM --Serialize--> XML
 */
public class SAML2ResponseBuilder {

	private static final Logger				LOGGER			= LoggerFactory.getLogger(SAML2ResponseBuilder.class);

	private static XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
	
	static {
		// a voir pour charger conf samlV2 si besoin.
    	try {
			OpenSamlBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			LOGGER.error("Error while initializing the OpenSAML library, loading default configurations.", e);
		}
	}
	
	public static Document marshallObjectToDocument(final XMLObject pInSamlObject) throws ParserConfigurationException, MessageEncodingException {

		Element lOutDomRoot;
		Document lOutDom = null;
		
		lOutDomRoot = marshallObject(pInSamlObject);
		
		try {
			lOutDom = Configuration.getParserPool().newDocument();
			lOutDom.appendChild(lOutDomRoot);
		} catch (XMLParserException e) {
			LOGGER.error("Error while creating a new document with a pooled builder. There probably was a problem retrieving a builder", e);
		}
		    
		return lOutDom;
	}

	// public static Element marshallObject(final XMLObject pInSamlObject) throws MarshallingException {
	// Element lOutDomRoot = null;
	//
	// // Get appropriate marshaler
	// MarshallerFactory lMarshallerFactory = Configuration.getMarshallerFactory();
	// Marshaller lMarshaller = lMarshallerFactory.getMarshaller(pInSamlObject);
	//
	// // Marshal using the saml java object
	// lOutDomRoot = lMarshaller.marshall(pInSamlObject);
	//
	// return lOutDomRoot;
	// }

	public static Element marshallObject(final XMLObject pInSamlObject) throws MessageEncodingException {
		LOGGER.trace("> marshallMessage()");
		Element lOutDomRoot = null;

		try {
			MarshallerFactory lMarshallerFactory = Configuration.getMarshallerFactory();
			Marshaller lMarshaller = lMarshallerFactory.getMarshaller(pInSamlObject);
			if (lMarshaller == null) {
				LOGGER.error("Unable to marshall message, no marshaller registered for message object: {}", pInSamlObject.getElementQName());
				throw new MessageEncodingException("Unable to marshall message, no marshaller registered for message object: " + pInSamlObject.getElementQName());
			}
			lOutDomRoot = lMarshaller.marshall(pInSamlObject);
			LOGGER.trace("Marshalled message into DOM:\n{}", XMLHelper.nodeToString(lOutDomRoot));
		} catch (MarshallingException e) {
			LOGGER.error("Encountered error marshalling message to its DOM representation", e);
			throw new MessageEncodingException("Encountered error marshalling message into its DOM representation", e);
		}

		LOGGER.trace("> marshallMessage()");
		return lOutDomRoot;
	}

	public static String serializeDOM(final Element pInDom) {
		LOGGER.trace("> serializeDOM()");

		String lOutXmlString = XMLHelper.nodeToString(pInDom);

		LOGGER.trace("< serializeDOM()");
		return lOutXmlString;
	}
	
	public static String marshallAndSerialize(final XMLObject pInSamlObject) throws MessageEncodingException {
		LOGGER.trace("> marshallAndSerialize()");

		// marshal saml java object
		Element lInDomRoot = marshallObject(pInSamlObject);

		// serialize DOM
		String lOutXmlString = serializeDOM(lInDomRoot);

		LOGGER.trace("< marshallAndSerialize()");
		return lOutXmlString;
	}

	public static byte[] deflate(final String pInXmlString) throws MessageEncodingException {
		LOGGER.trace("> deflateAndBase64Encode()");

		ByteArrayOutputStream lBytesArrayOutStream = null;
		try {
			lBytesArrayOutStream = new ByteArrayOutputStream();
			Deflater lDeflater = new Deflater(Deflater.DEFLATED, true);
			DeflaterOutputStream lDeflaterStream = new DeflaterOutputStream(lBytesArrayOutStream, lDeflater);
			lDeflaterStream.write(pInXmlString.getBytes("UTF-8"));
			lDeflaterStream.finish();
		} catch (IOException e) {
			throw new MessageEncodingException("Unable to DEFLATE and Base64 encode SAML message", e);
		}

		LOGGER.trace("< deflateAndBase64Encode()");
		return lBytesArrayOutStream.toByteArray();
	}

	public static String marshallSerializeDeflateAndBase64Encode(final XMLObject pInSamlObject) throws MessageEncodingException {
		LOGGER.trace("> marshallSerializeDeflateAndBase64Encode()");

		String lInXmlString = marshallAndSerialize(pInSamlObject);

		byte[] lOutDeflated = deflate(lInXmlString);

		String lOutBase64Deflated = Base64.encodeBytes(lOutDeflated, Base64.DONT_BREAK_LINES);

		LOGGER.trace("< marshallSerializeDeflateAndBase64Encode()");
		return lOutBase64Deflated;
	}
	
	/**
	 * Build a minimal response<br>
	 * 
	 * <pre>
	 * 
	 * {@code
	 * 	<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	 * 	xmlns:dp="http://www.datapower.com/schemas/management" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/"
	 * 	xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="1234"
	 * 	IssueInstant="2008-12-17T10:04:31Z" Version="2.0">
	 * }
	 * 
	 * </pre>
	 * 
	 * @param pIdResponse
	 *            optional argument, if null, a UUID is computed on the flow
	 * 
	 * @return Saml Response
	 */
	public static Response buildResponseEnveloppe(final String pIdResponse) {
		
		ResponseBuilder lResponseBuilder = (ResponseBuilder) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
    	Response lResponse = lResponseBuilder.buildObject();
    	
    	lResponse.setID(pIdResponse==null?"_"+UUID.randomUUID():pIdResponse);
    	lResponse.setIssueInstant(new DateTime());
    	return lResponse;
	}
	
	/**
	 * Add the response status to the response.<br>
	 * 
	 * <pre>
	 * {@code
	 * 	<samlp:Status value="samlp:Success" />
	 * }
	 * </pre>
	 * 
	 * @param pSamlResponse
	 * @param pStatusCode
	 */
	public static void addStatus(Response pSamlResponse, final String pStatusCode) {
		
		StatusBuilder lStatusBuilder = (StatusBuilder) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
    	Status lStatus = lStatusBuilder.buildObject();
    	
    	StatusCodeBuilder lStatusCodeBuilder = (StatusCodeBuilder) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
    	StatusCode lStatusCode = lStatusCodeBuilder.buildObject();
    	lStatusCode.setValue(pStatusCode);
    	lStatus.setStatusCode(lStatusCode);
    	pSamlResponse.setStatus(lStatus);
	}
	
	/**
	 * Add an "assertion" node to the response<br>
	 * 
	 * <pre>
	 * {@code
	 * 	<saml2:Assertion IssueInstant="2008-12-17T10:04:31Z">
	 * }
	 * </pre>
	 * 
	 * @param pSamlResponse
	 */
	public static Assertion buildAssertion(final Response pSamlResponse) {
		
		AssertionBuilder lAssertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
		Assertion lAssertion = lAssertionBuilder.buildObject();
		lAssertion.setIssueInstant(pSamlResponse.getIssueInstant());
		lAssertion.setVersion(SAMLVersion.VERSION_20);
		lAssertion.setParent(pSamlResponse);
		lAssertion.setID("_"+UUID.randomUUID());
		//assertion.setSubject(null);
		//assertion.setConditions(null);
		//assertion.getAuthnStatements().add(null);
		//assertion.getAttributeStatements().addAll(null);
		return lAssertion;
	}
	
	/**
	 * Add the response issuer to the response<br>
	 * 
	 * <pre>
	 * {@code
	 * 	<saml2:Issuer xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">Acme Corp</saml2:Issuer>
	 * }
	 * </pre>
	 * 
	 * @param pSamlResponse
	 * @param pIssuer
	 */
	public static void addResponseIssuer(Response pSamlResponse, final String pIssuer) {
		Issuer lIssuer = buildIssuer(pIssuer);
		lIssuer.setValue(pIssuer);
		pSamlResponse.setIssuer(lIssuer);
		
	}
	
	/**
	 * Add the assertion issuer to the assertion<br>
	 * 
	 * <pre>
	 * {@code
	 * 	<saml2:Issuer xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">Acme Corp</saml2:Issuer>
	 * }
	 * </pre>
	 * 
	 * @param pAssertion
	 * @param pIssuer
	 */
	public static void addAssertionIssuer(Assertion pAssertion, final String pIssuer) {
		
		Issuer lIssuer = buildIssuer(pIssuer);
		pAssertion.setIssuer(lIssuer);
	}
	
	
	/**
	 * Build an "Issuer" node that can be directly attached to a saml response or a saml assertion<br>
	 * 
	 * <pre>
	 * {@code
	 * 	<saml2:Issuer xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">Acme Corp</saml2:Issuer>
	 * 
	 * }
	 * 
	 * </pre>
	 * 
	 * @param pIssuer
	 * @return
	 */
	private static Issuer buildIssuer(final String pIssuer) {
		
		IssuerBuilder lIssuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer lIssuer = lIssuerBuilder.buildObject();
		lIssuer.setValue(pIssuer);
		return lIssuer;
	}
	
	/**
	 * Build a "Subject" node that can be directly attached to an "Assertion" node<br>
	 * 
	 * <pre>
	 * {@code
	 * <saml2:Subject xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
	 * 	<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">jdoe@si2m.fr</saml2:NameID>
	 * 	<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	 * 		<saml2:SubjectConfirmationData InResponseTo="_f886340fc1313bf3a314430448074055"
	 * 			NotBefore="2008-12-17T09:59:31Z" NotOnOrAfter="2008-12-17T10:14:31Z" 
	 * 			Recipient="https://www.SaaS.sp.endpoint/Shibboleth.sso/SAML2/POST" />
	 * 	</saml2:SubjectConfirmation>
	 * </saml2:Subject>
	 * }
	 * </pre>
	 * 
	 * @param pSubjectName
	 *            : [Mandatory] -
	 *            saml NameID value
	 * @param pValidityStart
	 *            : [Optional] -
	 *            saml SubjectConfirmationData "NotBefore" date constraint.
	 *            A time instant before which the subject cannot be confirmed.
	 * @param pValidityEnd
	 *            : [Optional] -
	 *            saml SubjectConfirmationData "NotOnOrAfter" date constraint.
	 *            A time instant at which the subject can no longer be confirmed.
	 * @param pInResponseTo
	 *            : [Optional] -
	 *            saml SubjectConfirmationData "InResponseTo" token constraint.
	 *            The ID of a SAML protocol message in response to which an attesting entity can present the assertion.
	 *            For example, this attribute might be used to correlate the assertion to a SAML request that resulted
	 *            in its presentation.
	 * @param pRecipient
	 *            : [Optional] - A URI specifying the entity or location to which an attesting entity can present the
	 *            assertion. For example, this attribute might indicate that the assertion must be delivered to a
	 *            particular network endpoint in order to prevent an intermediary from redirecting it someplace else.
	 * @param pSubjectNameIdFormat TODO
	 * @return Subject
	 */
	private static Subject buildSubject(@NotNull
	final String pSubjectName, final DateTime pValidityStart, final DateTime pValidityEnd, final String pInResponseTo, final URI pRecipient, final String pSubjectNameIdFormat) {
		
		String lRecipient = pRecipient==null?null:pRecipient.toString();
		
		// <Subject>
		SubjectBuilder lSubjectBuilder = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
		Subject lSubject = lSubjectBuilder.buildObject();
		
		// <NameID>
		NameIDBuilder lNameIdBuilder = (NameIDBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
		NameID lNameId = lNameIdBuilder.buildObject();
		lNameId.setFormat(pSubjectNameIdFormat);
		lNameId.setValue(pSubjectName);
		lSubject.setNameID(lNameId);
		
		// <SubjectConfirmation>
		SubjectConfirmationBuilder lSubjectConfirmationBuilder = (SubjectConfirmationBuilder) builderFactory.getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		SubjectConfirmation lSubjectConfirmation = lSubjectConfirmationBuilder.buildObject();
		lSubjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		lSubject.getSubjectConfirmations().add(lSubjectConfirmation);

		// <SubjectConfirmationData>
		SubjectConfirmationDataBuilder lSubjectConfirmationDataBuilder = (SubjectConfirmationDataBuilder) builderFactory.getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		SubjectConfirmationData lSubjectConfirmationData = lSubjectConfirmationDataBuilder.buildObject();
		lSubjectConfirmationData.setNotBefore(pValidityStart);
		lSubjectConfirmationData.setNotOnOrAfter(pValidityEnd);
		lSubjectConfirmationData.setRecipient(lRecipient);
		lSubjectConfirmationData.setInResponseTo(pInResponseTo);
			
		lSubjectConfirmation.setSubjectConfirmationData(lSubjectConfirmationData);
		
		return lSubject;
	}
	
	/**
	 * Add a "Subject" to an assertion<br>
	 * 
	 * <pre>
	 * {@code
	 * <saml2:Subject xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
	 * 	<saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">jdoe@si2m.fr</saml2:NameID>
	 * 	<saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
	 * 		<saml2:SubjectConfirmationData InResponseTo="_f886340fc1313bf3a314430448074055"
	 * 			NotBefore="2008-12-17T09:59:31Z" NotOnOrAfter="2008-12-17T10:14:31Z" 
	 * 			Recipient="https://www.SaaS.sp.endpoint/Shibboleth.sso/SAML2/POST" />
	 * 	</saml2:SubjectConfirmation>
	 * </saml2:Subject>
	 * }
	 * </pre>
	 * 
	 * @param pAssertion
	 *            : [Mandatory] - The saml Assertion the Subject must be attached to.
	 * @param pSubjectName
	 *            : [Mandatory] -
	 *            saml NameID value
	 * @param pValidityStart
	 *            : [Optional] -
	 *            saml SubjectConfirmationData "NotBefore" date constraint.
	 *            A time instant before which the subject cannot be confirmed.
	 * @param pValidityEnd
	 *            : [Optional] -
	 *            saml SubjectConfirmationData "NotOnOrAfter" date constraint.
	 *            A time instant at which the subject can no longer be confirmed.
	 * @param pInResponseTo
	 *            : [Optional] -
	 *            saml SubjectConfirmationData "InResponseTo" token constraint.
	 *            The ID of a SAML protocol message in response to which an attesting entity can present the assertion.
	 *            For example, this attribute might be used to correlate the assertion to a SAML request that resulted
	 *            in its presentation.
	 * @param pRecipient
	 *            : [Optional] - A URI specifying the entity or location to which an attesting entity can present the
	 *            assertion. For example, this attribute might indicate that the assertion must be delivered to a
	 *            particular network endpoint in order to prevent an intermediary from redirecting it someplace else.
	 *            resulted in its presentation.
	 * @param pSubjectNameIdFormat TODO
	 */
	public static void addSubject(@NotNull Assertion pAssertion, @NotNull
	final String pSubjectName, final DateTime pValidityStart, final DateTime pValidityEnd, final String pInResponseTo, final URI pRecipient, final String pSubjectNameIdFormat) {
		
		Subject subject = buildSubject(pSubjectName, pValidityStart, pValidityEnd, pInResponseTo, pRecipient, pSubjectNameIdFormat);
		pAssertion.setSubject(subject);
	}
	
	
	/**
	 * Build a "Conditions" node that could be directly attached to an "Assertion" parent node <br>
	 * 
	 * <pre>
	 * {@code
	 * <saml2:Conditions xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/"
	 * 	NotBefore="2008-12-17T09:59:31Z" NotOnOrAfter="2008-12-17T10:14:31Z" />
	 * }
	 * </pre>
	 * 
	 * @param pValidityStart
	 *            : [Optional] - saml Conditions element "NotBefore" date constraint. Specifies the earliest time
	 *            instant at which the assertion is valid.
	 * @param pValidityEnd
	 *            : [Optional] - saml Conditions element "NotOnOrAfter" date constraint. Specifies the time instant at
	 *            which the assertion has expired
	 * @param pAudienceRestrictionURIList
	 *            : [Optional] - Specifies that the assertion is addressed to to one or more specific audiences
	 *            identified by {@code<Audience>} elements.<br>
	 *            An {@code<Audience>} is a URI reference that identifies an intended audience. The URI reference MAY
	 *            identify a document that describes the terms and conditions of audience membership. It MAY also
	 *            contain the unique identifier URI from a SAML name identifier that describes a system entity<br>
	 *            The audience restriction condition evaluates to Valid if and only if the SAML relying party is a
	 *            member of one or more of the audiences specified.<br>
	 * @return Conditions
	 */
	private static Conditions buildConditions(final DateTime pValidityStart, final DateTime pValidityEnd, final List<URI> pAudienceRestrictionURIList) {
		
		ConditionsBuilder lConditionsBuilder = (ConditionsBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
		AudienceRestriction lAudienceRestriction = null;
		Audience lAudience = null;
		Conditions lConditions = lConditionsBuilder.buildObject();
		lConditions.setNotBefore(pValidityStart);
		lConditions.setNotOnOrAfter(pValidityEnd);
		if (pAudienceRestrictionURIList != null && pAudienceRestrictionURIList.size() > 0) {
			lAudienceRestriction = ((AudienceRestrictionBuilder) builderFactory.getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME)).buildObject();
			for (URI uri : pAudienceRestrictionURIList) {
				lAudience = ((AudienceBuilder) builderFactory.getBuilder(Audience.DEFAULT_ELEMENT_NAME)).buildObject();
				lAudience.setAudienceURI(uri.toString());
				lAudienceRestriction.getAudiences().add(lAudience);
			}
			lConditions.getAudienceRestrictions().add(lAudienceRestriction);
		}
		return lConditions;
	}
	
	
	/**
	 * Add the structure that represents a condition to the request's assertion
	 * 
	 * <pre>
	 * {@code
	 * <saml2:Conditions xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/"
	 * 		NotBefore="2008-12-17T09:59:31Z" NotOnOrAfter="2008-12-17T10:14:31Z" />
	 * }
	 * </pre>
	 * 
	 * @param pAssertion
	 *            : [Mandatory] - The saml Assertion the Conditions element must be attached to.
	 * @param pValidityStart
	 *            : [Optional] - saml Conditions element "NotBefore" date constraint. Specifies the earliest time
	 *            instant at which the assertion is valid.
	 * @param pValidityEnd
	 *            : [Optional] - saml Conditions element "NotOnOrAfter" date constraint. Specifies the time instant at
	 *            which the assertion has expired
	 * @param pAudienceRestrictionURIList
	 *            : [Optional] - Specifies that the assertion is addressed to to one or more specific audiences
	 *            identified by {@code<Audience>} elements.<br>
	 *            An {@code<Audience>} is a URI reference that identifies an intended audience. The URI reference MAY
	 *            identify a document that describes the terms and conditions of audience membership. It MAY also
	 *            contain the unique identifier URI from a SAML name identifier that describes a system entity<br>
	 *            The audience restriction condition evaluates to Valid if and only if the SAML relying party is a
	 *            member of one or more of the audiences specified.<br>
	 * @return
	 */
	public static void addConditions(@NotNull Assertion pAssertion, final DateTime pValidityStart, final DateTime pValidityEnd, final List<URI> pAudienceRestrictionURIList) {
		
		Conditions lConditions = buildConditions(pValidityStart, pValidityEnd, pAudienceRestrictionURIList);
		pAssertion.setConditions(lConditions);
	}
	
	
	/**
	 * Build an "AuthnStatement" node wich can be directly attached to an "assertion" node<br>
	 * 
	 * <pre>
	 * {@code
	 * <saml2:AuthnStatement xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" AuthnInstant="2008-12-17T10:04:31Z" SessionNotOnOrAfter="2008-12-17T10:14:31Z">
	 * 	<saml2:SubjectLocality Address="Acme_Corp_SAML_Authentication" />
	 * 	<saml2:AuthnContext>
	 * 		<saml2:AuthnContextClassRef>
	 * 			urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified
	 * 		</saml2:AuthnContextClassRef>
	 * 	</saml2:AuthnContext>
	 * </saml2:AuthnStatement>
	 * 
	 * The <AuthnStatement> element describes a statement by the SAML authority asserting that the
	 * assertion subject was authenticated by a particular means at a particular time. Assertions containing
	 * <AuthnStatement> elements MUST contain a <Subject> element.
	 * 
	 * }
	 * </pre>
	 * 
	 * @param pValidityStart
	 * @param pValidityEnd
	 * @param pSubjectIssuerIPaddress
	 *            The network address of the system from which the principal identified by the subject was
	 *            authenticated. IPv4 addresses SHOULD be represented in dotted-decimal format (e.g., "1.2.3.4").
	 *            IPv6 addresses SHOULD be represented as defined by Section 2.2 of IETF RFC 3513 [RFC 3513]
	 *            (e.g., "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210").
	 * @param pSubjectIssuerDnsName
	 *            The DNS name of the system from which the principal identified by the subject was authenticated.
	 * @param pAuthnContextClassRef TODO
	 */
	private static AuthnStatement buildAuthStatement(final DateTime pValidityStart, final DateTime pValidityEnd, final String pSubjectIssuerIPaddress, final String pSubjectIssuerDnsName, String pAuthnContextClassRef) {
		
		AuthnStatementBuilder lAuthStatBuilder = (AuthnStatementBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
		AuthnStatement lAuthStat = lAuthStatBuilder.buildObject();
		lAuthStat.setAuthnInstant(pValidityStart);
		lAuthStat.setSessionNotOnOrAfter(pValidityEnd);
		SubjectLocalityBuilder lSubjectLocalityBuilder = (SubjectLocalityBuilder) builderFactory.getBuilder(SubjectLocality.DEFAULT_ELEMENT_NAME);
		if (pSubjectIssuerIPaddress != null || pSubjectIssuerDnsName != null) {
			SubjectLocality lSubjectLocality = lSubjectLocalityBuilder.buildObject();
			lSubjectLocality.setAddress(pSubjectIssuerIPaddress);
			lSubjectLocality.setDNSName(pSubjectIssuerDnsName);
			lAuthStat.setSubjectLocality(lSubjectLocality);
		}
		AuthnContextBuilder lAuthnContextBuilder = (AuthnContextBuilder) builderFactory.getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
		AuthnContext lAuthnContext = lAuthnContextBuilder.buildObject();
		AuthnContextClassRefBuilder lAuthnContextClassRefBuilder = (AuthnContextClassRefBuilder) builderFactory.getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		AuthnContextClassRef lAuthnContextClassRef = lAuthnContextClassRefBuilder.buildObject();
		lAuthnContextClassRef.setAuthnContextClassRef(pAuthnContextClassRef);
		lAuthnContext.setAuthnContextClassRef(lAuthnContextClassRef);
		lAuthStat.setAuthnContext(lAuthnContext);
		return lAuthStat;
	}
	
	/**
	 * Add an "AuthnStatement" node directly to the "assertion" node<br>
	 * 
	 * <pre>
	 * {@code
	 * <saml2:AuthnStatement xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/" AuthnInstant="2008-12-17T10:04:31Z" SessionNotOnOrAfter="2008-12-17T10:14:31Z">
	 * 	<saml2:SubjectLocality Address="Acme_Corp_SAML_Authentication" />
	 * 	<saml2:AuthnContext>
	 * 		<saml2:AuthnContextClassRef>
	 * 			urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified
	 * 		</saml2:AuthnContextClassRef>
	 * 	</saml2:AuthnContext>
	 * </saml2:AuthnStatement>
	 * }
	 * </pre>
	 * 
	 * @param pAssertion
	 *            : [Mandatory] - The saml Assertion the AuthnStatements element must be attached to.
	 * @param pValidityStart
	 * @param pValidityEnd
	 * @param pSubjectIssuerIPaddress
	 *            The network address of the system from which the principal identified by the subject was
	 *            authenticated. IPv4 addresses SHOULD be represented in dotted-decimal format (e.g., "1.2.3.4").
	 *            IPv6 addresses SHOULD be represented as defined by Section 2.2 of IETF RFC 3513 [RFC 3513]
	 *            (e.g., "FEDC:BA98:7654:3210:FEDC:BA98:7654:3210").
	 * @param pSubjectIssuerDsnName
	 *            The DNS name of the system from which the principal identified by the subject was authenticated.
	 * @param pAuthnContextClassRef TODO
	 */
	public static void addAuthnStatement(@NotNull Assertion pAssertion, final DateTime pValidityStart, final DateTime pValidityEnd, final String pSubjectIssuerIPaddress,
			final String pSubjectIssuerDsnName, final String pAuthnContextClassRef) {
		
		AuthnStatement lAuthStatement = buildAuthStatement(pValidityStart, pValidityEnd, pSubjectIssuerIPaddress, pSubjectIssuerDsnName, pAuthnContextClassRef);
		pAssertion.getAuthnStatements().add(lAuthStatement);
	}
	
	/**
	 * Build an "AttributeStatement" node wich can be directly attached to an "assertion" node<br>
	 * 
	 * <pre>
	 * {@code
	 * <saml2:AttributeStatement>
	 * 	<saml2:Attribute Name="ApplicationID">
	 * 		<saml2:AttributeValue>test</saml2:AttributeValue>
	 * 	</saml2:Attribute>
	 * 	<saml2:Attribute Name="CompanyID">
	 * 		<saml2:AttributeValue>FR200612190416756</saml2:AttributeValue>
	 * 	</saml2:Attribute>
	 * </saml2:AttributeStatement>
	 * }
	 * </pre>
	 * 
	 * @param pAttributeMap
	 *            the map owning the names and values of the attributes to include in the saml AttributeStatement
	 * @return AttributeStatement
	 */
	@SuppressWarnings("unchecked")
	private static AttributeStatement buildAttributeStatement(@NotNull
	final Map pAttributeMap) {
		
		AttributeStatementBuilder lAttStatBuilder = (AttributeStatementBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
		AttributeStatement lAttStat = lAttStatBuilder.buildObject();
		AttributeBuilder lAttBuilder = null;
		Attribute lAtt = null;
		XMLObjectBuilder<XSString> lAttValueBuilder = null;
		
		for (Iterator<String> lIter = pAttributeMap.keySet().iterator(); lIter.hasNext();) {
			String lAttributeName = lIter.next();

			if (lAttBuilder == null || lAttValueBuilder == null) {
				lAttBuilder = (AttributeBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
				lAttValueBuilder = (XMLObjectBuilder<XSString>) builderFactory.getBuilder(XSString.TYPE_NAME);
			}

			lAtt = lAttBuilder.buildObject();
			lAtt.setName(lAttributeName);
						
			XSString lAttValue = (XSString) lAttValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
			lAttValue.setValue((String) pAttributeMap.get(lAttributeName));
			
			lAtt.getAttributeValues().add((XMLObject) lAttValue);
			lAttStat.getAttributes().add(lAtt);
		}
		return lAttStat;
	}
	
	/**
	 * Add an "AttributeStatement" node directly to the "Assertion" node<br>
	 * 
	 * <pre>
	 * {@code
	 * <saml2:AttributeStatement>
	 * 	<saml2:Attribute Name="ApplicationID">
	 * 		<saml2:AttributeValue>test</saml2:AttributeValue>
	 * 	</saml2:Attribute>
	 * 	<saml2:Attribute Name="CompanyID">
	 * 		<saml2:AttributeValue>FR200612190416756</saml2:AttributeValue>
	 * 	</saml2:Attribute>
	 * </saml2:AttributeStatement>
	 * }
	 * </pre>
	 * 
	 * @param pAssertion
	 * @param pAttributeMap
	 */
	public static void addAttributeStatement(Assertion pAssertion, Map pAttributeMap) {
		AttributeStatement lAttStatement = buildAttributeStatement(pAttributeMap);
		addAttributeStatement(pAssertion, lAttStatement);
	}
	
	public static void addAttributeStatement(@NotNull Assertion pAssertion, final AttributeStatement pAttributeStatement) {
		if (pAttributeStatement != null) {
			pAssertion.getAttributeStatements().add(pAttributeStatement);
		}
	}
	
	/**
	 * Add an "Attribute" node to the "AttributeStatement" node
	 * 
	 * @param pAttributeStatement
	 *            created if null
	 * @param pAttName
	 *            required
	 * @param pAttNameFormat
	 *            not set if null
	 * @param pAttFriendlyName
	 *            not set if null
	 * @param pAttValue
	 *            required
	 * 
	 * @return the created and/or modified pAttributeStatement
	 */
	public static AttributeStatement addAttributeToAttributeStatement(AttributeStatement pAttributeStatement, final String pAttName, final String pAttNameFormat, final String pAttFriendlyName,
			final Object pAttValue) {
		Attribute lAttribute = null;
		if (pAttName != null && pAttValue != null) {
			lAttribute = buildAttribute(pAttName, pAttNameFormat, pAttFriendlyName, pAttValue);
		}
		return addAttributeToAttributeStatement(pAttributeStatement, lAttribute);
	}

	public static AttributeStatement addAttributeToAttributeStatement(AttributeStatement pAttributeStatement, final Attribute pAttribute) {
		AttributeStatement lAttributeStatement = pAttributeStatement;
		if (lAttributeStatement == null) {
			AttributeStatementBuilder lAttStatBuilder = (AttributeStatementBuilder) builderFactory.getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
			lAttributeStatement = lAttStatBuilder.buildObject();
		}
		lAttributeStatement.getAttributes().add(pAttribute);
		return lAttributeStatement;
	}

	public static Attribute buildAttribute(final String pAttName, final String pAttNameFormat, final String pAttFriendlyName, final Object pAttValue) {
		AttributeBuilder lAttBuilder = null;
		Attribute lAttribute = null;
		
		XMLObjectBuilder<XSString> lAttValueBuilder = null;
		XSString lAttValue = null;
		
		lAttBuilder = (AttributeBuilder) builderFactory.getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
		lAttribute = lAttBuilder.buildObject();
		lAttribute.setName(pAttName);
		if (pAttNameFormat!=null) {
			lAttribute.setNameFormat(pAttNameFormat);
		}
		lAttribute.setFriendlyName(pAttFriendlyName);

		lAttValueBuilder = (XMLObjectBuilder<XSString>) builderFactory.getBuilder(XSString.TYPE_NAME);
		
		if (pAttValue instanceof String) {
			lAttValue = (XSString) lAttValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
			lAttValue.setValue((String) pAttValue);

			lAttribute.getAttributeValues().add((XMLObject) lAttValue);
		} else if (pAttValue instanceof List) {
			Iterator<String> lIter = ((List<String>) pAttValue).iterator();
			while (lIter.hasNext()) {
				String lString = lIter.next();
				lAttValue = (XSString) lAttValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
				lAttValue.setValue(lString);

				lAttribute.getAttributeValues().add((XMLObject) lAttValue);
			}
		} else {
			// to complex exception pprrrrrrrrrrt
		}
		
		return lAttribute;
	}
	
	/**
	 * This method aims to attach a signature to a SignableSAMLObject.
	 * 
	 * @see <a href="https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUserManJavaDSIG">https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUserManJavaDSIG</a> for more details
	 * 
	 * @param pSignableObject
	 * @param pCredential
	 * @return
	 */
	public static Signature attachSignatureToSignableSAMLObject(SignableSAMLObject pSignableObject, final Credential pCredential) {
		// https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUserManJavaDSIG
		
		KeyInfo lKeyInfo = getKeyInfo(pCredential);
		
		// Attaching a Signature to the SignableSAMLObject
		Signature lSignature = computeSignature(pSignableObject, pCredential, lKeyInfo);
		pSignableObject.setSignature(lSignature);
		
		((SAMLObjectContentReference)lSignature.getContentReferences().get(0)).setDigestAlgorithm(EncryptionConstants.ALGO_ID_DIGEST_SHA256);
		
		return lSignature;
	}
	
	private static KeyInfo getKeyInfo(final Credential pCredential) {
		SecurityConfiguration lSecurityConf = Configuration.getGlobalSecurityConfiguration();
		NamedKeyInfoGeneratorManager lNamedKiGenManager = lSecurityConf.getKeyInfoGeneratorManager();
		KeyInfoGeneratorManager lKiGenManager = lNamedKiGenManager.getDefaultManager();
		KeyInfoGeneratorFactory lKiGenFact = null;
		KeyInfoGenerator lKiGen = null;
		KeyInfo lKeyInfo = null;
		
		lKiGenFact = lKiGenManager.getFactory(pCredential);
		lKiGen = lKiGenFact.newInstance();
		try {
			lKeyInfo = lKiGen.generate(pCredential);
		} catch (SecurityException e) {
			LOGGER.error("Error while generating a new KeyInfo object based on keying material and other information within a credential.", e);
		}
		
//		lKiGenFact = new X509KeyInfoGeneratorFactory();
//		lKiGen = lKiGenFact.newInstance();
//		try {
//			lKeyInfo = lKiGen.generate(pCredential);
//		} catch (SecurityException e) {
//			// TODO gestion Loggs
//			System.out.println("SAML2ResponseBuilder.getKeyInfo() : "+e);
//			e.printStackTrace();
//		}
//
//		KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder) builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);
//		lKeyInfo = (KeyInfo) keyInfoBuilder.buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);
//		X509Certificate certificate = (X509Certificate) ks.getCertificate("xxxxx");
//		pCredential.setEntityCertificate(certificate);
//		KeyInfoHelper.addPublicKey(lKeyInfo, certificate.getPublicKey());
//		KeyInfoHelper.addCertificate(lKeyInfo, certificate);
		
		return lKeyInfo;
	}

	private static Signature computeSignature(final SignableSAMLObject pSignableObject, final Credential pCredential, final KeyInfo pKeyInfo) {
		Signature lSignature = ((SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME)).buildObject();
		lSignature.setSigningCredential(pCredential);
		lSignature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		lSignature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		
		lSignature.setKeyInfo(pKeyInfo);
		return lSignature;
	}
	
	public static String zlibDeflate(final byte[] pBytes) {
		final ByteArrayInputStream lBais = new ByteArrayInputStream(pBytes);
		final ByteArrayOutputStream lBaos = new ByteArrayOutputStream();
		final InflaterInputStream lIis = new InflaterInputStream(lBais);
		final byte[] lBuf = new byte[1024];

		try {
			int lCount = lIis.read(lBuf);
			while (lCount != -1) {
				lBaos.write(lBuf, 0, lCount);
				lCount = lIis.read(lBuf);
			}
			return new String(lBaos.toByteArray());
		} catch (final IOException e) {
			LOGGER.error("I/O error occurs while reading up to byte.length bytes of data an input stream into an array of bytes", e);
			return null;
		} finally {
			try {
				lIis.close();
			} catch (final IOException e) {
				LOGGER.error("I/O error occurs while closing an input stream and releasing any system resources associated with this stream ", e);
			}
		}
	}
}
