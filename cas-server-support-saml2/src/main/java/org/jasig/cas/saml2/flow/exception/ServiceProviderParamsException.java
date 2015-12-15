package org.jasig.cas.saml2.flow.exception;

import org.springframework.webflow.core.FlowException;

public class ServiceProviderParamsException extends FlowException {

	public ServiceProviderParamsException(final String pMsg) {
		super(pMsg);
	}

}
