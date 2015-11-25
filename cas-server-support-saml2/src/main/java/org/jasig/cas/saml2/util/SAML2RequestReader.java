package org.jasig.cas.saml2.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

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
import org.opensaml.xml.parse.ParserPool;
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

	private SAML2RequestReader() {
	}

	public static Document parseXML(final String pInXml) throws XMLParserException {
		LOGGER.trace("> parseXML()");

		// Get parser pool manager
		ParserPool lBasicParserPool;

		lBasicParserPool = Configuration.getParserPool();

		Reader lInXml = new StringReader(pInXml);
		Document lOutDom;

		// Parse SAML Request
		lOutDom = lBasicParserPool.parse(lInXml);

		LOGGER.trace("< parseXML()");
		return lOutDom;
	}

	public static XMLObject unmarshallDOM(final Document pInDom) throws UnmarshallingException {
		LOGGER.trace("> unmarshallDOM()");

		Element lInDomRoot = null;
		XMLObject lOpenSamlXMLObject;
		lInDomRoot = pInDom.getDocumentElement();

		// Get appropriate unmarshaller
		UnmarshallerFactory lUnmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller lUnmarshaller = lUnmarshallerFactory.getUnmarshaller(lInDomRoot);

		// Unmarshall using the document root element
		lOpenSamlXMLObject = lUnmarshaller.unmarshall(lInDomRoot);

		LOGGER.trace("< unmarshallDOM()");
		return lOpenSamlXMLObject;
	}

	public static XMLObject parseAndUnmarshall(final String pInXml) throws XMLParserException, UnmarshallingException {
		LOGGER.trace("> parseAndUnmarshall()");

		Document lInDom = null;
		XMLObject lOpenSamlXMLObject = null;
		// Parse SAML
		lInDom = parseXML(pInXml);

		// Unmarshall DOM
		lOpenSamlXMLObject = unmarshallDOM(lInDom);

		LOGGER.trace("< parseAndUnmarshall()");
		return lOpenSamlXMLObject;
	}

	public static AuthnRequest getAuthnRequest(final String pXmlSamlRequest) {
		LOGGER.trace("> getAuthnRequest()");

		AuthnRequest lAuthnRequest = null;
		try {
			lAuthnRequest = (AuthnRequest) parseAndUnmarshall(pXmlSamlRequest);
		} catch (XMLParserException e) {
			LOGGER.error("Error while parsing an XML file using a pooled builder. It could be due to a problem retrieving a builder, the input stream can not be read, or the XML was invalid", e);
		} catch (UnmarshallingException e) {
			LOGGER.error("Error while wnmarshalling the given W3C DOM element into a XMLObject.", e);
		}

		LOGGER.trace("< getAuthnRequest()");
		return lAuthnRequest;
	}

	public static String getIssuerValue(final AuthnRequest pAuthnRequest) {
		LOGGER.trace("> getIssuerValue()");

		Issuer lIssuer = pAuthnRequest.getIssuer();
		String lIssuerValue = null;

		if (lIssuer != null) {
			lIssuerValue = lIssuer.getValue();
		}

		LOGGER.trace("< getIssuerValue()");
		return lIssuerValue;
	}

	public static String decodeXMLAuthnRequest(final String pEncodedRequestXmlString) {
		LOGGER.trace("> decodeXMLAuthnRequest()");

		String lDecodedXMLAuthnRequest = null;
		if (pEncodedRequestXmlString != null) {
			byte[] lDecodedBytes;
			if ((lDecodedBytes = SAML2RequestReader.base64Decode(pEncodedRequestXmlString)) != null) {
				lDecodedXMLAuthnRequest = SAML2RequestReader.inflate(lDecodedBytes);
			}
		}

		LOGGER.trace("< decodeXMLAuthnRequest()");
		return lDecodedXMLAuthnRequest;
	}

	public static byte[] base64Decode(final String pXml) {
		LOGGER.trace("> base64Decode()");

		byte[] lXmlBytes = null;
		try {
			lXmlBytes = pXml.getBytes("UTF-8");
			lXmlBytes = Base64.decodeBase64(lXmlBytes);
		} catch (final UnsupportedEncodingException e) {
			LOGGER.error("Error while encoding a string into a sequence of bytes using the named charset. Occurs if the named charset is not supported", e);
		}

		LOGGER.trace("< base64Decode()");
		return lXmlBytes;
	}

	public static String inflate(final byte[] pBytes) {
		LOGGER.trace("> inflate()");

		String lUncompressedString = null;
		final Inflater lInflater = new Inflater(true);
		byte[] lXmlMessageBytes = new byte[10000];

		final byte[] lExtendedBytes = new byte[pBytes.length + 1];
		System.arraycopy(pBytes, 0, lExtendedBytes, 0, pBytes.length);
		lExtendedBytes[pBytes.length] = 0;

		lInflater.setInput(lExtendedBytes);

		try {
			final int resultLength = lInflater.inflate(lXmlMessageBytes);
			lInflater.end();

			if (!lInflater.finished()) {
				LOGGER.error("buffer not large enough.");
				throw new RuntimeException("buffer not large enough.");
			}

			lInflater.end();
			lUncompressedString = new String(lXmlMessageBytes, 0, resultLength, "UTF-8");
		} catch (final DataFormatException e) {
			LOGGER.warn("Problem encountered while uncompressing byte array into specified buffer. Occurs if the compressed data format is invalid", e);
		} catch (final UnsupportedEncodingException e) {
			LOGGER.error("Cannot find encoding: UTF-8", e);
			throw new RuntimeException("Cannot find encoding: UTF-8", e);
		}

		if (lUncompressedString == null) {

			final ByteArrayInputStream lBais = new ByteArrayInputStream(pBytes);
			final ByteArrayOutputStream lBaos = new ByteArrayOutputStream();
			final InflaterInputStream lIis = new InflaterInputStream(lBais);
			lXmlMessageBytes = new byte[1024];

			try {
				int count = lIis.read(lXmlMessageBytes);
				while (count != -1) {
					lBaos.write(lXmlMessageBytes, 0, count);
					count = lIis.read(lXmlMessageBytes);
				}
				lUncompressedString = new String(lBaos.toByteArray());
			} catch (final IOException e) {
				LOGGER.error("Unable to read bytes of data from this input stream into an array of bytes", e);
			} finally {
				try {
					lIis.close();
				} catch (final IOException e) {
					// nothing to do
				}
			}
		}

		LOGGER.trace("< inflate()");
		return lUncompressedString;
	}
}
