package org.jasig.cas.saml2.support;

import java.util.ArrayList;
import java.util.List;


public enum CaseTransformer implements Transformer {
	NONE, UPPERCASE, LOWERCASE;

	public String transform(final String pInputString) {
		switch (this) {
		case UPPERCASE:
			return pInputString.toUpperCase();
		case LOWERCASE:
			return pInputString.toLowerCase();
		default:
			return pInputString;
		}
	}


	@Override
	public Object transform(Object pInputString) {
		if (pInputString.getClass().isInstance(String.class)) {
			return transform((String) pInputString);
		} else if (pInputString.getClass().isInstance(List.class)) {
			List<String> lInStringList = (List<String>) pInputString;
			List<String> lOutStringList = new ArrayList<String>(((List<String>) pInputString).size());
			int i = 0;
			for (String lString : lInStringList) {
				lOutStringList.set(i++, transform(lString));
			}
			return lOutStringList;
		}
		return pInputString;
	}
}
