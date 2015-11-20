package org.jasig.cas.saml2.util;

import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.Configuration;
import org.opensaml.OpenSamlBootstrap;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
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
public class SAML2RequestReader {
	
	private static final Logger	LOGGER	= LoggerFactory.getLogger(SAML2RequestReader.class);

	static {
		// a voir pour charger conf samlV2 si besoin.
		try {
			// Initialize the library
			OpenSamlBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			LOGGER.error("Error in initializing the OpenSAML library, loading default configurations.", e);
		}
	}

	public static Document parseXML(final String pInXml) throws XMLParserException {
		// Get parser pool manager
		BasicParserPool lBasicParserPool = new BasicParserPool();
		lBasicParserPool.setNamespaceAware(true);

		Reader lInXml = new StringReader(pInXml);
		Document lOutDom = null;

		// Parse SAML Request
		lOutDom = lBasicParserPool.parse(lInXml);

		return lOutDom;
	}

	public static XMLObject unmarshallDOM(final Document pInDom) throws UnmarshallingException {
		Element lInDomRoot = null;
		XMLObject lOpenSamlXMLObject = null;
		lInDomRoot = pInDom.getDocumentElement();

		// Get apropriate unmarshaller
		UnmarshallerFactory lUnmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller lUnmarshaller = lUnmarshallerFactory.getUnmarshaller(lInDomRoot);

		// Unmarshall using the document root element
		lOpenSamlXMLObject = lUnmarshaller.unmarshall(lInDomRoot);
		return lOpenSamlXMLObject;
	}

	public static XMLObject parseAndUnmarshall(final String pInXml) throws XMLParserException, UnmarshallingException {
		Document lInDom = null;
		XMLObject lOpenSamlXMLObject = null;
		// Parse SAML
		lInDom = parseXML(pInXml);

		// Unmarshall DOM
		lOpenSamlXMLObject = unmarshallDOM(lInDom);
		return lOpenSamlXMLObject;
	}

	public static AuthnRequest getAuthnRequest(final String pXmlSamlRequest) {
		AuthnRequest lAuthnRequest = null;
		try {
			lAuthnRequest = (AuthnRequest) parseAndUnmarshall(pXmlSamlRequest);
		} catch (XMLParserException e) {
			// TODO Logger
			System.err.println(e);
			e.printStackTrace();
		} catch (UnmarshallingException e) {
			// TODO Logger
			System.err.println(e);
			e.printStackTrace();
		}
		return lAuthnRequest;
	}

	public static String getIssuerValue(final AuthnRequest pAuthnRequest) {
		Issuer lIssuer = pAuthnRequest.getIssuer();
		return lIssuer.getValue();
	}

	public static String decodeAuthnRequestXML(final String pEncodedRequestXmlString) {
		if (pEncodedRequestXmlString == null) {
			return null;
		}

		final byte[] lDecodedBytes = SAML2RequestReader.base64Decode(pEncodedRequestXmlString);

		if (lDecodedBytes == null) {
			return null;
		}

		final String lInflated = SAML2RequestReader.inflate(lDecodedBytes);

		if (lInflated != null) {
			return lInflated;
		}
		// TODO check if this piece of code is correct, I don't understand why you deflate a non-deflated message
		return SAML2ResponseBuilder.zlibDeflate(lDecodedBytes);
	}

	public static byte[] base64Decode(final String pXml) {
		try {
			final byte[] lXmlBytes = pXml.getBytes("UTF-8");
			return Base64.decodeBase64(lXmlBytes);
		} catch (final Exception e) {
			return null;
		}
	}

	public static String inflate(final byte[] pBytes) {
		final Inflater lInflater = new Inflater(true);
		final byte[] lXmlMessageBytes = new byte[10000];

		final byte[] lExtendedBytes = new byte[pBytes.length + 1];
		System.arraycopy(pBytes, 0, lExtendedBytes, 0, pBytes.length);
		lExtendedBytes[pBytes.length] = 0;

		lInflater.setInput(lExtendedBytes);

		try {
			final int resultLength = lInflater.inflate(lXmlMessageBytes);
			lInflater.end();

			if (!lInflater.finished()) {
				throw new RuntimeException("buffer not large enough.");
			}

			lInflater.end();
			return new String(lXmlMessageBytes, 0, resultLength, "UTF-8");
		} catch (final DataFormatException e) {
			return null;
		} catch (final UnsupportedEncodingException e) {
			throw new RuntimeException("Cannot find encoding: UTF-8", e);
		}
	}
}
