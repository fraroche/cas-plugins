package org.jasig.cas.saml2.support;

import java.util.List;

import org.jasig.cas.authentication.principal.Principal;

public class CasToSaml2PrincipalMapper {

	/**
	 * Allow to replace the SAML response Subject/NameID obtained from the "CasToSaml2Principal.getId()" by the value of any
	 * attribute present in this CasToSaml2Principal.
	 */
	private String					alternateId;
	private Transformer				idTransformer	= AttributeMapper.NOOP_TRANSFORMER;
	private List<AttributeMapper>	attributesMappingList;

	/**
	 * @param pAlternateId
	 *            the alternateId to set
	 */
	public void setAlternateId(final String pAlternateId) {
		alternateId = pAlternateId;
	}

	/**
	 * @param pIdTransformer
	 *            the idTransformer to set
	 */
	public void setIdTransformer(Transformer pIdTransformer) {
		idTransformer = pIdTransformer;
	}

	/**
	 * @param pAttributesMappingList
	 *            the attributesMappingList to set
	 */
	public void setAttributesMappingList(final List<AttributeMapper> pAttributesMappingList) {
		attributesMappingList = pAttributesMappingList;
	}

	/**
	 * @return the alternateId
	 */
	public String getAlternateId() {
		return alternateId;
	}

	/**
	 * @return the idTransformer
	 */
	public Transformer getIdTransformer() {
		return idTransformer;
	}

	/**
	 * @return the attributesMappingList
	 */
	public List<AttributeMapper> getAttributesMappingList() {
		return attributesMappingList;
	}

	public AttributeMapper getAttributeMapper(final String pCasAttributeName) {
		AttributeMapper lOutAttributeMapper = null;
		for (AttributeMapper lAttributeMapper : attributesMappingList) {
			if (pCasAttributeName.equals(lAttributeMapper.getMappedCasPrincipalAttributeName())) {
				lOutAttributeMapper = lAttributeMapper;
				break;
			}
		}
		return lOutAttributeMapper;
	}

	public String getId(final Principal pCasPrincipal) {
		String lIdValue;
	
		if (this.alternateId == null || this.alternateId.isEmpty()) {
			lIdValue = pCasPrincipal.getId();
		} else {
			lIdValue = (String) pCasPrincipal.getAttributes().get(this.alternateId);
			if (lIdValue == null) {
				lIdValue = pCasPrincipal.getId();
			}
		}
		lIdValue = (String) this.idTransformer.transform(lIdValue);
	
		return lIdValue;
	}
}
