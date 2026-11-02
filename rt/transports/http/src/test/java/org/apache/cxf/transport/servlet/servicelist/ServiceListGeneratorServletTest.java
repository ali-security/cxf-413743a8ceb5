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
package org.apache.cxf.transport.servlet.servicelist;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import org.apache.cxf.message.Message;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.service.model.InterfaceInfo;
import org.apache.cxf.service.model.ServiceInfo;
import org.apache.cxf.transport.AbstractDestination;
import org.apache.cxf.transport.Conduit;
import org.apache.cxf.transport.http.DestinationRegistry;
import org.apache.cxf.transport.servlet.ServletController;
import org.easymock.EasyMock;

import org.junit.Assert;
import org.junit.Test;

/**
 * Renders the formatted services list page through a real ServletController and
 * ServiceListGeneratorServlet and checks that matrix parameters injected into the
 * request URL are not reflected back to the client (CVE-2016-6812).
 */
public class ServiceListGeneratorServletTest extends Assert {
    private static final String HOST = "http://localhost:8080";
    private static final String NS = "http://cxf.apache.org/greeter_control";

    private static String getServicesPage(String requestUri, String contextPath,
                                          String servletPath, String pathInfo) throws Exception {
        return getServicesPage(requestUri, contextPath, servletPath, pathInfo,
                               new HashMap<String, String>());
    }

    private static String getServicesPage(String requestUri, String contextPath,
                                          String servletPath, String pathInfo,
                                          Map<String, String> parameters) throws Exception {
        EndpointInfo ei = new EndpointInfo();
        ei.setAddress("/bookstore");
        AbstractDestination dest = new TestDestination(ei);

        ServiceInfo si = new ServiceInfo();
        si.setName(new QName(NS, "BasicGreeterService"));
        si.setTargetNamespace(NS);
        InterfaceInfo ii = new InterfaceInfo(si, new QName(NS, "Greeter"));
        ii.addOperation(new QName(NS, "greetMe"));
        EndpointInfo soapEi = new EndpointInfo(si, "http://schemas.xmlsoap.org/wsdl/soap/");
        soapEi.setName(new QName(NS, "GreeterPort"));
        soapEi.setAddress("/SoapContext/GreeterPort");
        AbstractDestination soapDest = new TestDestination(soapEi);

        DestinationRegistry registry = EasyMock.createNiceMock(DestinationRegistry.class);
        registry.getSortedDestinations();
        EasyMock.expectLastCall().andReturn(new AbstractDestination[] {dest, soapDest}).anyTimes();

        StringWriter out = new StringWriter();
        HttpServletResponse res = EasyMock.createNiceMock(HttpServletResponse.class);
        res.getWriter();
        EasyMock.expectLastCall().andReturn(new PrintWriter(out)).anyTimes();

        EasyMock.replay(registry, res);

        ServiceListGeneratorServlet serviceListGenerator = new ServiceListGeneratorServlet(registry, null);
        ServletController controller = new ServletController(registry, null, serviceListGenerator);
        controller.invoke(new TestRequest(requestUri, contextPath, servletPath, pathInfo, parameters), res);
        return out.toString();
    }

    @Test
    public void testGetServicesPage() throws Exception {
        String s = getServicesPage("/the/services", "", "/the", "/services");
        assertTrue(s, s.contains("href=\"/the/services/?stylesheet=1\""));
        assertTrue(s, s.contains("<title>CXF - Service list</title>"));
        assertTrue(s, s.contains("<a href=\"" + HOST + "/the/bookstore?_wadl\""));
    }

    @Test
    public void testGetServicesPageNotFound() throws Exception {
        String s = getServicesPage("/the/services;a=b", "", "/the", "/services");
        assertFalse(s, s.contains("<title>CXF - Service list</title>"));
        assertFalse(s, s.contains(";a=b"));
        assertTrue(s, s.contains("No service was found."));
    }

    @Test
    public void testGetServicesPageWithServletPatternMatchOnly() throws Exception {
        String s = getServicesPage("/the/;a=b", "", "/the", "/");
        assertTrue(s, s.contains("href=\"/the/?stylesheet=1\""));
        assertTrue(s, s.contains("<title>CXF - Service list</title>"));
        assertFalse(s, s.contains(";a=b"));
        assertTrue(s, s.contains("<a href=\"" + HOST + "/the/bookstore?_wadl\""));
    }

    @Test
    public void testGetServicesPageWithServletPatternMatchOnly2() throws Exception {
        String s = getServicesPage("/services;a=b;/list;a=b/;a=b", "", "/services/list", "/");
        assertTrue(s, s.contains("href=\"/services/list/?stylesheet=1\""));
        assertTrue(s, s.contains("<title>CXF - Service list</title>"));
        assertFalse(s, s.contains(";a=b"));
        assertTrue(s, s.contains("<a href=\"" + HOST + "/services/list/bookstore?_wadl\""));
    }

    @Test
    public void testGetServicesPageWithContextPathAndMatrixParams() throws Exception {
        String s = getServicesPage("/ctx;a=b/the;c=d/;e=f", "/ctx", "/the", "/");
        assertTrue(s, s.contains("href=\"/ctx/the/?stylesheet=1\""));
        assertFalse(s, s.contains(";a=b"));
        assertFalse(s, s.contains(";c=d"));
        assertFalse(s, s.contains(";e=f"));
        assertTrue(s, s.contains("<a href=\"" + HOST + "/ctx/the/bookstore?_wadl\""));
    }

    @Test
    public void testGetServicesPageWithInjectedScriptMatrixParam() throws Exception {
        String payload = ";jsessionid=%22%3E%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E";
        String s = getServicesPage("/the/" + payload, "", "/the", "/");
        assertTrue(s, s.contains("<title>CXF - Service list</title>"));
        assertFalse(s, s.contains("jsessionid"));
        assertFalse(s, s.contains("%3Cscript%3E"));
        assertFalse(s, s.contains("alert("));
        assertTrue(s, s.contains("href=\"/the/?stylesheet=1\""));
        assertTrue(s, s.contains("<a href=\"" + HOST + "/the/bookstore?_wadl\""));
    }

    @Test
    public void testGetServicesPageWithServletPathTrailingSlash() throws Exception {
        String s = getServicesPage("/the/", "", "/the", "/");
        assertTrue(s, s.contains("href=\"/the/?stylesheet=1\""));
        assertTrue(s, s.contains("<a href=\"" + HOST + "/the/bookstore?_wadl\""));
        assertFalse(s, s.contains("/the//bookstore"));
    }

    @Test
    public void testServiceListing() throws Exception {
        String s = getServicesPage("/service_listing/services", "/service_listing", "/services", null);
        assertTrue(s, s.contains(HOST + "/service_listing/services/bookstore"));
        assertTrue(s, s.contains(HOST + "/service_listing/services/SoapContext/GreeterPort"));
    }

    @Test
    public void testServiceListingUnformatted() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("formatted", "false");
        String s = getServicesPage("/service_listing/services", "/service_listing", "/services", null, params);
        assertFalse(s, s.contains("<title>CXF - Service list</title>"));
        assertTrue(s, s.contains(HOST + "/service_listing/services/bookstore"));
        assertTrue(s, s.contains(HOST + "/service_listing/services/SoapContext/GreeterPort"));
    }

    @Test
    public void testEscapeHTML() throws Exception {
        String s = getServicesPage("/service_listing/services/<script>alert(1)</script>/../../",
                                   "/service_listing", "/services", "/");
        assertTrue(s, s.contains("<title>CXF - Service list</title>"));
        assertFalse(s, s.contains("<script>"));
        String escapedBase = HOST + "/service_listing/services/&lt;script&gt;alert(1)&lt;/script&gt;/../..";
        assertTrue(s, s.contains("<a href=\"" + escapedBase + "/bookstore?_wadl\""));
        assertTrue(s, s.contains("<a href=\"" + escapedBase + "/SoapContext/GreeterPort?wsdl\""));
    }

    @Test
    public void testEscapeHTMLUnformatted() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("formatted", "false");
        String s = getServicesPage("/service_listing/services/<script>alert(1)</script>/../../",
                                   "/service_listing", "/services", "/", params);
        assertFalse(s, s.contains("<script>"));
        String escapedBase = HOST + "/service_listing/services/&lt;script&gt;alert(1)&lt;/script&gt;/../../";
        assertTrue(s, s.contains(escapedBase + "/bookstore?_wadl"));
        assertTrue(s, s.contains(escapedBase + "/SoapContext/GreeterPort"));
    }

    private static class TestRequest extends HttpServletRequestWrapper {
        private final String requestUri;
        private final String contextPath;
        private final String servletPath;
        private final String pathInfo;
        private final Map<String, String> parameters;
        private final Map<String, Object> attributes = new HashMap<String, Object>();

        TestRequest(String requestUri, String contextPath, String servletPath, String pathInfo,
                    Map<String, String> parameters) {
            super(createDelegate());
            this.requestUri = requestUri;
            this.contextPath = contextPath;
            this.servletPath = servletPath;
            this.pathInfo = pathInfo;
            this.parameters = parameters;
        }

        private static HttpServletRequest createDelegate() {
            HttpServletRequest delegate = EasyMock.createNiceMock(HttpServletRequest.class);
            EasyMock.replay(delegate);
            return delegate;
        }

        @Override
        public StringBuffer getRequestURL() {
            return new StringBuffer(HOST + requestUri);
        }

        @Override
        public String getRequestURI() {
            return requestUri;
        }

        @Override
        public String getContextPath() {
            return contextPath;
        }

        @Override
        public String getServletPath() {
            return servletPath;
        }

        @Override
        public String getPathInfo() {
            return pathInfo;
        }

        @Override
        public String getParameter(String name) {
            return parameters.get(name);
        }

        @Override
        public Object getAttribute(String name) {
            return attributes.get(name);
        }

        @Override
        public void setAttribute(String name, Object o) {
            attributes.put(name, o);
        }

        @Override
        public void removeAttribute(String name) {
            attributes.remove(name);
        }
    }

    private static class TestDestination extends AbstractDestination {
        private static final Logger LOG = Logger.getLogger(TestDestination.class.getName());

        TestDestination(EndpointInfo ei) {
            super(null, ei);
        }

        @Override
        protected Conduit getInbuiltBackChannel(Message inMessage) {
            return null;
        }

        @Override
        protected Logger getLogger() {
            return LOG;
        }
    }
}
