package org.jasig.cas.saml2.support;

import javax.validation.constraints.NotNull;

import org.jasig.cas.authentication.principal.Principal;

public class AttributeMapper {

	/**
	 * This constant is to be used in Spring configuration XML file when you need to reference a Saml Attribute value.<br>
	 * ex:
	 * 
	 * <pre>
	 * {@code
	 * <property name="casTosaml2PrincipalMapper">
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
	 * 
	 * PRINCIPAL_ID references the CAS CasToSaml2Principal.id,
	 */

	public static final String		PRINCIPAL_ID			= "PrincipalId";
	public static final Transformer	NOOP_TRANSFORMER		= new Transformer() {
																@Override
																public Object transform(Object pObject) {
																	return pObject;
																}
															};

	// Name [Required]
	@NotNull
	private final String				samlAttributeName;

	@NotNull
	private final String				mappedCasPrincipalAttributeName;

	// NameFormat [Optional]
	private String						samlAttributeNameFormat;

	// FriendlyName [Optional]
	private String						samlAttributeFriendlyName;

	private Transformer					attributeTransformer	= NOOP_TRANSFORMER;

	public AttributeMapper(final String samlAttributeName, final String mappedCasPrincipalAttributeName) {
		this.samlAttributeName = samlAttributeName;
		this.mappedCasPrincipalAttributeName = mappedCasPrincipalAttributeName;
	}

	/**
	 * @param pSamlAttributeNameFormat
	 *            the samlAttributeNameFormat to set
	 */
	public void setSamlAttributeNameFormat(String pSamlAttributeNameFormat) {
		this.samlAttributeNameFormat = pSamlAttributeNameFormat;
	}

	/**
	 * @param pSamlAttributeFriendlyName
	 *            the samlAttributeFriendlyName to set
	 */
	public void setSamlAttributeFriendlyName(String pSamlAttributeFriendlyName) {
		this.samlAttributeFriendlyName = pSamlAttributeFriendlyName;
	}

	/**
	 * @param pAttributeTransformer
	 *            the attributeTransformer to set
	 */
	public void setAttributeTransformer(Transformer pAttributeTransformer) {
		this.attributeTransformer = pAttributeTransformer;
	}

	/**
	 * @return the samlAttributeName
	 */
	public String getSamlAttributeName() {
		return samlAttributeName;
	}

	/**
	 * @return the mappedCasPrincipalAttributeName
	 */
	public String getMappedCasPrincipalAttributeName() {
		return mappedCasPrincipalAttributeName;
	}

	/**
	 * @return the samlAttributeNameFormat
	 */
	public String getSamlAttributeNameFormat() {
		return samlAttributeNameFormat;
	}

	/**
	 * @return the samlAttributeFriendlyName
	 */
	public String getSamlAttributeFriendlyName() {
		return samlAttributeFriendlyName;
	}

	public Object getSamlAttributeValue(final Principal pCasPrincipal) {
		Object lAttributeValue;

		if (PRINCIPAL_ID.equals(this.mappedCasPrincipalAttributeName)) {
			lAttributeValue = pCasPrincipal.getId();
		} else {
			lAttributeValue = pCasPrincipal.getAttributes().get(this.mappedCasPrincipalAttributeName);
			if (lAttributeValue == null) {
				lAttributeValue = pCasPrincipal.getId();
			}
		}
		lAttributeValue = this.attributeTransformer.transform(lAttributeValue);

		return lAttributeValue;
	}
}
