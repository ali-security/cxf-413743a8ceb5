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
package org.apache.cxf.transport.servlet;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.cxf.Bus;
import org.easymock.EasyMock;

import org.junit.Assert;
import org.junit.Test;

public class AbstractHTTPServletTest extends Assert {

    private static final String DIRECTORY_LISTING = "META-INF/\norg/\n";

    private ByteArrayOutputStream responseBody;

    @Test
    public void testStaticResourcesDoNotMatchQueryWithRedirectQueryCheck() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("static-resources-list", ".*\\.html");
        params.put("redirect-query-check", "true");
        TestServlet servlet = createServlet(params);

        servlet.handleRequest(createRequest("/", ".html"), createResponse());

        assertTrue("Static resource must not be served for a query-only match",
                   servlet.requestedResources.isEmpty());
        assertFalse("Directory listing must not be exposed",
                    responseBody.toString("UTF-8").contains("META-INF"));
        assertEquals(1, servlet.invokeCount);
        assertEquals(0, servlet.redirectCount);
    }

    @Test
    public void testStaticResourcesDoNotMatchQueryWithoutRedirectQueryCheck() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("static-resources-list", ".*\\.html");
        TestServlet servlet = createServlet(params);

        servlet.handleRequest(createRequest("/", ".html"), createResponse());

        assertTrue(servlet.requestedResources.isEmpty());
        assertEquals(1, servlet.invokeCount);
    }

    @Test
    public void testStaticResourceServed() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("static-resources-list", ".*\\.html");
        params.put("redirect-query-check", "true");
        TestServlet servlet = createServlet(params);

        servlet.handleRequest(createRequest("/index.html", null), createResponse());

        assertEquals(Collections.singletonList("/index.html"), servlet.requestedResources);
        assertEquals(0, servlet.invokeCount);
    }

    @Test
    public void testStaticResourceWithQueryServedWithRedirectQueryCheck() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("static-resources-list", ".*\\.html");
        params.put("redirect-query-check", "true");
        TestServlet servlet = createServlet(params);

        servlet.handleRequest(createRequest("/index.html", "a=b"), createResponse());

        // static resources are matched against the path only, never against the query
        assertEquals(Collections.singletonList("/index.html"), servlet.requestedResources);
        assertEquals(0, servlet.invokeCount);
    }

    @Test
    public void testRedirectListMatchesQueryWithRedirectQueryCheck() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("redirects-list", ".*\\?wsdl");
        params.put("redirect-servlet-name", "otherServlet");
        params.put("redirect-query-check", "true");
        TestServlet servlet = createServlet(params);

        servlet.handleRequest(createRequest("/service", "wsdl"), createResponse());

        assertEquals(1, servlet.redirectCount);
        assertEquals(0, servlet.invokeCount);
    }

    @Test
    public void testRedirectListIgnoresQueryWithoutRedirectQueryCheck() throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("redirects-list", ".*\\?wsdl");
        params.put("redirect-servlet-name", "otherServlet");
        TestServlet servlet = createServlet(params);

        servlet.handleRequest(createRequest("/service", "wsdl"), createResponse());

        assertEquals(0, servlet.redirectCount);
        assertEquals(1, servlet.invokeCount);
    }

    private TestServlet createServlet(final Map<String, String> params) throws ServletException {
        TestServlet servlet = new TestServlet();
        servlet.init(new ServletConfig() {
            public String getServletName() {
                return "testServlet";
            }
            public ServletContext getServletContext() {
                return null;
            }
            public String getInitParameter(String name) {
                return params.get(name);
            }
            public Enumeration<String> getInitParameterNames() {
                return Collections.enumeration(params.keySet());
            }
        });
        return servlet;
    }

    private HttpServletRequest createRequest(String pathInfo, String queryString) {
        HttpServletRequest request = EasyMock.createNiceMock(HttpServletRequest.class);
        EasyMock.expect(request.getPathInfo()).andReturn(pathInfo).anyTimes();
        EasyMock.expect(request.getQueryString()).andReturn(queryString).anyTimes();
        EasyMock.replay(request);
        return request;
    }

    private HttpServletResponse createResponse() throws IOException {
        responseBody = new ByteArrayOutputStream();
        final ByteArrayOutputStream body = responseBody;
        HttpServletResponse response = EasyMock.createNiceMock(HttpServletResponse.class);
        EasyMock.expect(response.getOutputStream()).andReturn(new ServletOutputStream() {
            @Override
            public void write(int b) throws IOException {
                body.write(b);
            }
        }).anyTimes();
        EasyMock.replay(response);
        return response;
    }

    private static class TestServlet extends AbstractHTTPServlet {
        private static final long serialVersionUID = 1L;

        private List<String> requestedResources = new ArrayList<String>();
        private int invokeCount;
        private int redirectCount;

        @Override
        protected Bus getBus() {
            return null;
        }

        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
            chain.doFilter(request, response);
        }

        @Override
        protected InputStream getResourceAsStream(String path) {
            requestedResources.add(path);
            // emulate a class loader returning a directory listing for a directory resource
            return new ByteArrayInputStream(DIRECTORY_LISTING.getBytes());
        }

        @Override
        protected void invoke(HttpServletRequest request, HttpServletResponse response)
            throws ServletException {
            invokeCount++;
        }

        @Override
        protected void redirect(HttpServletRequest request, HttpServletResponse response, String pathInfo)
            throws ServletException {
            redirectCount++;
        }
    }
}
