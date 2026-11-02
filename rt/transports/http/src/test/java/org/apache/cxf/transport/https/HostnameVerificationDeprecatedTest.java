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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.net.URLStreamHandler;
import java.security.KeyStore;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.apache.cxf.configuration.jsse.TLSClientParameters;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * A test for hostname verification when the deprecated "com.sun.net.ssl.internal.www.protocol" https
 * protocol handler is used (e.g. when the Java system property "java.protocol.handler.pkgs" is set to
 * "com.sun.net.ssl.internal.www.protocol"). This means that com.sun.net.ssl.HostnameVerifier is used
 * instead of the javax version.
 */
public class HostnameVerificationDeprecatedTest extends Assert {

    private static final String DEPRECATED_HANDLER =
        "com.sun.net.ssl.internal.www.protocol.https.Handler";
    private static final String RESPONSE = "Hello Kitty";
    private static final int TIMEOUT = 30000;

    private static SSLServerSocket serverSocket;
    private static TrustManagerFactory trustManagerFactory;

    // The server presents a certificate for "CN=Bethal", which does not match "localhost".
    @BeforeClass
    public static void startServer() throws Exception {
        KeyStore keyStore = loadKeyStore();
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "password".toCharArray());
        trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        serverSocket = (SSLServerSocket)ctx.getServerSocketFactory().createServerSocket(0);

        Thread serverThread = new Thread(new Runnable() {
            public void run() {
                serve();
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    @AfterClass
    public static void stopServer() throws Exception {
        if (serverSocket != null) {
            serverSocket.close();
        }
    }

    // Here we expect an exception, as the default hostname verifier contributed by CXF will object to the
    // fact that the server certificate does not have "CN=localhost".
    @Test
    public void testLocalhostNotMatching() throws Exception {
        HttpURLConnection connection = openDeprecatedConnection(createTLSClientParameters());
        try {
            readResponse(connection);
            fail("Failure expected on the hostname verification");
        } catch (IOException ex) {
            // expected
        } finally {
            connection.disconnect();
        }
    }

    // A user-supplied javax.net.ssl.HostnameVerifier cannot be mapped onto the deprecated
    // com.sun.net.ssl.HostnameVerifier contract, so the verification must fail closed.
    @Test
    public void testCustomJavaxVerifierFailsClosed() throws Exception {
        TLSClientParameters params = createTLSClientParameters();
        params.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String host, SSLSession session) {
                return false;
            }
        });
        HttpURLConnection connection = openDeprecatedConnection(params);
        try {
            readResponse(connection);
            fail("Failure expected on the hostname verification");
        } catch (IOException ex) {
            // expected
        } finally {
            connection.disconnect();
        }
    }

    // Disabling the CN check must still allow the call through the deprecated handler.
    @Test
    public void testDisableCNCheck() throws Exception {
        TLSClientParameters params = createTLSClientParameters();
        params.setDisableCNCheck(true);
        HttpURLConnection connection = openDeprecatedConnection(params);
        try {
            assertEquals(RESPONSE, readResponse(connection));
        } finally {
            connection.disconnect();
        }
    }

    @Test
    public void testDefaultVerifierDeprecatedContract() throws Exception {
        HttpURLConnection connection = openDeprecatedConnection(createTLSClientParameters());
        assertFalse(verifyDeprecated(connection, "localhost", "Bethal"));
        assertFalse(verifyDeprecated(connection, "www.evil.com", "www.foo.com"));
        assertFalse(verifyDeprecated(connection, "localhost", ""));
        assertFalse(verifyDeprecated(connection, "localhost", null));
        assertTrue(verifyDeprecated(connection, "localhost", "localhost"));
        assertTrue(verifyDeprecated(connection, "www.foo.com", "WWW.FOO.COM"));
        assertTrue(verifyDeprecated(connection, "a.foo.com", "*.foo.com"));
    }

    @Test
    public void testAllowAllVerifierDeprecatedContract() throws Exception {
        TLSClientParameters params = createTLSClientParameters();
        params.setDisableCNCheck(true);
        HttpURLConnection connection = openDeprecatedConnection(params);
        assertTrue(verifyDeprecated(connection, "localhost", "Bethal"));
        assertFalse(verifyDeprecated(connection, "localhost", ""));
        assertFalse(verifyDeprecated(connection, "localhost", null));
    }

    @Test
    public void testCustomJavaxVerifierDeprecatedContract() throws Exception {
        TLSClientParameters params = createTLSClientParameters();
        params.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String host, SSLSession session) {
                return false;
            }
        });
        HttpURLConnection connection = openDeprecatedConnection(params);
        assertFalse(verifyDeprecated(connection, "localhost", "Bethal"));
        assertFalse(verifyDeprecated(connection, "localhost", null));
    }

    private static TLSClientParameters createTLSClientParameters() {
        TLSClientParameters params = new TLSClientParameters();
        params.setTrustManagers(trustManagerFactory.getTrustManagers());
        return params;
    }

    private static HttpURLConnection openDeprecatedConnection(TLSClientParameters params) throws Exception {
        URLStreamHandler handler = (URLStreamHandler)Class.forName(DEPRECATED_HANDLER).newInstance();
        URL url = new URL(null, "https://localhost:" + serverSocket.getLocalPort() + "/", handler);
        HttpURLConnection connection = new HttpsURLConnectionFactory().createConnection(params, null, url);
        assertFalse("Expected the deprecated com.sun.net.ssl connection",
                    connection instanceof HttpsURLConnection);
        connection.setConnectTimeout(TIMEOUT);
        connection.setReadTimeout(TIMEOUT);
        return connection;
    }

    private static boolean verifyDeprecated(HttpURLConnection connection, String host, String certHostname)
        throws Exception {
        Method getter = connection.getClass().getMethod("getHostnameVerifier");
        Object verifier = getter.invoke(connection);
        assertNotNull(verifier);
        Method verify = getter.getReturnType().getMethod("verify", String.class, String.class);
        return (Boolean)verify.invoke(verifier, host, certHostname);
    }

    private static String readResponse(HttpURLConnection connection) throws IOException {
        assertEquals(200, connection.getResponseCode());
        InputStream in = connection.getInputStream();
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n = in.read(buf);
            while (n != -1) {
                bout.write(buf, 0, n);
                n = in.read(buf);
            }
            return new String(bout.toByteArray(), "UTF-8");
        } finally {
            in.close();
        }
    }

    private static KeyStore loadKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream in = HostnameVerificationDeprecatedTest.class.getResourceAsStream("resources/Bethal.jks");
        assertNotNull("Bethal.jks not found", in);
        try {
            keyStore.load(in, "password".toCharArray());
        } finally {
            in.close();
        }
        return keyStore;
    }

    private static void serve() {
        while (!serverSocket.isClosed()) {
            Socket socket = null;
            try {
                socket = serverSocket.accept();
                socket.setSoTimeout(TIMEOUT);
                handleRequest(socket);
            } catch (IOException ex) {
                // the client may legitimately abort the connection after the TLS handshake
            } finally {
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (IOException ex) {
                        // ignore
                    }
                }
            }
        }
    }

    private static void handleRequest(Socket socket) throws IOException {
        InputStream in = socket.getInputStream();
        // consume the request headers up to the terminating empty line
        int matched = 0;
        int c = in.read();
        while (c != -1 && matched < 4) {
            if (c == '\r') {
                matched = matched == 2 ? 3 : 1;
            } else if (c == '\n' && (matched == 1 || matched == 3)) {
                matched++;
            } else {
                matched = 0;
            }
            if (matched < 4) {
                c = in.read();
            }
        }
        if (c == -1) {
            return;
        }
        byte[] body = RESPONSE.getBytes("UTF-8");
        OutputStream out = socket.getOutputStream();
        out.write(("HTTP/1.1 200 OK\r\n"
            + "Content-Type: text/plain\r\n"
            + "Content-Length: " + body.length + "\r\n"
            + "Connection: close\r\n\r\n").getBytes("US-ASCII"));
        out.write(body);
        out.flush();
    }
}
