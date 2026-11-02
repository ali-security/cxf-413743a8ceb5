/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.cxf.transport.https;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;

import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;

public class CertificateHostnameVerifierTest extends Assert {

    private static final CertificateHostnameVerifier[] VERIFIERS = {
        CertificateHostnameVerifier.DEFAULT,
        CertificateHostnameVerifier.DEFAULT_AND_LOCALHOST,
        CertificateHostnameVerifier.STRICT,
        CertificateHostnameVerifier.STRICT_IE6
    };

    @Test
    public void testGetCNsSingle() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, OU=Dev, O=Foo, C=US");
        assertCNs(new String[] {"www.foo.com"}, CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testGetCNsMultipleKeepsMostSpecificFirst() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, CN=www.bar.com, O=Foo");
        assertCNs(new String[] {"www.foo.com", "www.bar.com"},
                  CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testGetCNsMultiValuedRdn() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com+OU=Dev, O=Foo");
        assertCNs(new String[] {"www.foo.com"}, CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testGetCNsNoCN() throws Exception {
        X509Certificate cert = mockCertificate("OU=Dev, O=Foo, C=US");
        assertNull(CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testGetCNsIgnoresCNInsideQuotedValue() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, OU=\"foo,CN=www.evil.com,bar\", O=Foo");
        assertCNs(new String[] {"www.foo.com"}, CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testGetCNsIgnoresCNSubstringInValue() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, OU=\"CN=www.evil.com\", O=Foo");
        assertCNs(new String[] {"www.foo.com"}, CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testGetCNsIgnoresCNAfterEscapedPlus() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, OU=\"foo+CN=www.evil.com\", O=Foo");
        assertCNs(new String[] {"www.foo.com"}, CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testGetCNsInjectedCNOnly() throws Exception {
        X509Certificate cert = mockCertificate("O=\"Evil,CN=www.evil.com,Inc\", C=US");
        assertNull(CertificateHostnameVerifier.Certificates.getCNs(cert));
    }

    @Test
    public void testCheckAcceptsGenuineCN() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, OU=Dev, O=Foo");
        for (CertificateHostnameVerifier verifier : VERIFIERS) {
            verifier.check("www.foo.com", cert);
            assertTrue(verifier.toString(), verifier.verify("www.foo.com", mockSession(cert)));
        }
    }

    @Test
    public void testCheckOnlyFirstCNUnlessIE6() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, CN=www.bar.com, O=Foo");
        CertificateHostnameVerifier.DEFAULT.check("www.foo.com", cert);
        CertificateHostnameVerifier.STRICT_IE6.check("www.bar.com", cert);
        assertRejected(CertificateHostnameVerifier.DEFAULT, "www.bar.com", cert);
        assertRejected(CertificateHostnameVerifier.STRICT, "www.bar.com", cert);
    }

    @Test
    public void testCheckRejectsCNInjectedBeforeGenuineCN() throws Exception {
        X509Certificate cert = mockCertificate("OU=\"foo,CN=www.evil.com,bar\", CN=www.foo.com, O=Foo");
        for (CertificateHostnameVerifier verifier : VERIFIERS) {
            assertRejected(verifier, "www.evil.com", cert);
            verifier.check("www.foo.com", cert);
        }
    }

    @Test
    public void testCheckRejectsCNInjectedAfterGenuineCN() throws Exception {
        X509Certificate cert = mockCertificate("CN=www.foo.com, OU=\"foo,CN=www.evil.com,bar\", O=Foo");
        for (CertificateHostnameVerifier verifier : VERIFIERS) {
            assertRejected(verifier, "www.evil.com", cert);
        }
    }

    @Test
    public void testCheckRejectsInjectedCNWithoutGenuineCN() throws Exception {
        X509Certificate cert = mockCertificate("O=\"Evil,CN=www.evil.com,Inc\", C=US");
        for (CertificateHostnameVerifier verifier : VERIFIERS) {
            assertRejected(verifier, "www.evil.com", cert);
        }
    }

    private static void assertRejected(CertificateHostnameVerifier verifier, String host,
                                       X509Certificate cert) throws Exception {
        try {
            verifier.check(host, cert);
            fail(verifier + " accepted " + host + " for "
                 + cert.getSubjectX500Principal().getName(X500Principal.RFC2253));
        } catch (SSLException ex) {
            // expected
        }
        assertFalse(verifier.toString(), verifier.verify(host, mockSession(cert)));
    }

    private static void assertCNs(String[] expected, String[] actual) {
        assertNotNull(actual);
        assertEquals(Arrays.asList(expected), Arrays.asList(actual));
    }

    private static X509Certificate mockCertificate(String subject) throws Exception {
        X509Certificate cert = EasyMock.createMock(X509Certificate.class);
        EasyMock.expect(cert.getSubjectX500Principal()).andReturn(new X500Principal(subject)).anyTimes();
        EasyMock.expect(cert.getSubjectAlternativeNames()).andReturn(null).anyTimes();
        EasyMock.replay(cert);
        return cert;
    }

    private static SSLSession mockSession(X509Certificate cert) throws Exception {
        SSLSession session = EasyMock.createMock(SSLSession.class);
        EasyMock.expect(session.getPeerCertificates()).andReturn(new Certificate[] {cert}).anyTimes();
        EasyMock.replay(session);
        return session;
    }
}
