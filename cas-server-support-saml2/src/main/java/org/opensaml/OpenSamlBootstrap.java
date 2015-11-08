package org.opensaml;

import java.util.HashMap;
import java.util.Map;

import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.opensaml.xml.parse.XMLParserException;

public class OpenSamlBootstrap extends DefaultBootstrap {
	/**
	 * Initializes the OpenSAML library, loading default configurations.
	 * 
	 * @throws ConfigurationException
	 *             thrown if there is a problem initializing the OpenSAML library
	 */
	public static synchronized void bootstrap() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
		initializeParserPool();
	}

	/**
	 * Initializes the default global parser pool instance.
	 * 
	 * <p>
	 * The ParserPool configured by default here is an instance of {@link StaticBasicParserPool}, with a maxPoolSize
	 * property of 50 and all other properties with default values.
	 * </p>
	 * 
	 * <p>
	 * If a deployment wishes to use a different parser pool implementation, or one configured with different
	 * characteristics, they may either override this method, or simply configure a different ParserPool after
	 * bootstrapping via {@link Configuration#setParserPool(org.opensaml.xml.parse.ParserPool)}.
	 * </p>
	 * 
	 * @throws ConfigurationException
	 *             thrown if there is a problem initializing the parser pool
	 */
	protected static void initializeParserPool() throws ConfigurationException {
		StaticBasicParserPool pp = new StaticBasicParserPool();

		Map<String, Boolean> docBuilderFactoryFeatures = new HashMap<String, Boolean>();
		// this is to prevent XML External Entity (XXE) Processing
		docBuilderFactoryFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", true);
		docBuilderFactoryFeatures.put("http://xml.org/sax/features/external-general-entities", false);
		docBuilderFactoryFeatures.put("http://xml.org/sax/features/external-parameter-entities", false);
		pp.setBuilderFeatures(docBuilderFactoryFeatures);
		pp.setXincludeAware(false);
		pp.setExpandEntityReferences(false);
		pp.setNamespaceAware(true);
		pp.setMaxPoolSize(50);
		try {
			pp.initialize();
		} catch (XMLParserException e) {
			throw new ConfigurationException("Error initializing parser pool", e);
		}
		Configuration.setParserPool(pp);
	}
}
