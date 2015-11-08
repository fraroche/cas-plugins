package org.jasig.cas.saml2.util;

import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.validation.constraints.NotNull;

import org.opensaml.xml.security.x509.X509Util;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.Resource;

public class X509CertificateFactoryBean extends AbstractFactoryBean {

    @NotNull
    private Resource resource;

    protected final Object createInstance() throws Exception {
        final InputStream certificate = this.resource.getInputStream();
        try {
            final byte[] certifBytes = new byte[certificate.available()];
            certificate.read(certifBytes);
            Collection<X509Certificate> x509certCollection = X509Util.decodeCertificate(certifBytes);
    		X509Certificate x509Certificate = (X509Certificate) x509certCollection.iterator().next();
    		return x509Certificate;
        } finally {
            certificate.close();
        }
    }

    public Class getObjectType() {
        return PublicKey.class;
    }
    

    public void setLocation(final Resource resource) {
        this.resource = resource;
    }
}
