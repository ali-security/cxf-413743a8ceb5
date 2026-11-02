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
import java.util.Collections;
import java.util.Map;
import java.util.logging.Logger;

import javax.xml.namespace.QName;

import org.apache.cxf.message.Message;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.service.model.InterfaceInfo;
import org.apache.cxf.service.model.ServiceInfo;
import org.apache.cxf.transport.AbstractDestination;
import org.apache.cxf.transport.Conduit;

import org.junit.Assert;
import org.junit.Test;

public class FormattedServiceListWriterTest extends Assert {
    private static final String NS = "http://cxf.apache.org/greeter_control";
    private static final String BASE = "http://localhost:8080/service_listing/services";
    private static final String SCRIPT_BASE = BASE + "/<script>alert(1)</script>/../../";
    private static final String ESCAPED_SCRIPT_BASE =
        BASE + "/&lt;script&gt;alert(1)&lt;/script&gt;/../../";

    private static String writeServiceList(String basePath,
                                           AbstractDestination[] soap,
                                           AbstractDestination[] rest,
                                           Map<String, String> atomMap) throws Exception {
        StringWriter out = new StringWriter();
        PrintWriter pw = new PrintWriter(out);
        FormattedServiceListWriter writer =
            new FormattedServiceListWriter("/service_listing/services/?stylesheet=1", null, false, atomMap);
        writer.writeServiceList(pw, basePath, soap, rest);
        pw.flush();
        return out.toString();
    }

    private static AbstractDestination soapDestination(String address) {
        ServiceInfo si = new ServiceInfo();
        si.setName(new QName(NS, "BasicGreeterService"));
        si.setTargetNamespace(NS);
        InterfaceInfo ii = new InterfaceInfo(si, new QName(NS, "Greeter"));
        ii.addOperation(new QName(NS, "greetMe"));
        EndpointInfo ei = new EndpointInfo(si, "http://schemas.xmlsoap.org/wsdl/soap/");
        ei.setName(new QName(NS, "GreeterPort"));
        ei.setAddress(address);
        return new TestDestination(ei);
    }

    private static AbstractDestination restDestination(String address) {
        EndpointInfo ei = new EndpointInfo();
        ei.setAddress(address);
        return new TestDestination(ei);
    }

    @Test
    public void testSoapEndpointAddressEscaped() throws Exception {
        String s = writeServiceList(SCRIPT_BASE,
                                    new AbstractDestination[] {soapDestination("/SoapContext/GreeterPort")},
                                    new AbstractDestination[0], null);
        assertFalse(s, s.contains("<script>"));
        assertTrue(s, s.contains("<span class=\"value\">" + ESCAPED_SCRIPT_BASE
                                 + "SoapContext/GreeterPort</span>"));
        assertTrue(s, s.contains("<a href=\"" + ESCAPED_SCRIPT_BASE + "SoapContext/GreeterPort?wsdl\">"));
    }

    @Test
    public void testRestEndpointAddressEscaped() throws Exception {
        String s = writeServiceList(SCRIPT_BASE, new AbstractDestination[0],
                                    new AbstractDestination[] {restDestination("/resources")}, null);
        assertFalse(s, s.contains("<script>"));
        assertTrue(s, s.contains("<span class=\"value\">" + ESCAPED_SCRIPT_BASE + "resources</span>"));
        assertTrue(s, s.contains("<a href=\"" + ESCAPED_SCRIPT_BASE + "resources?_wadl\">"
                                 + ESCAPED_SCRIPT_BASE + "resources?_wadl</a>"));
    }

    @Test
    public void testEndpointAddressAttributeBreakoutEscaped() throws Exception {
        String base = BASE + "/\"onmouseover=\"alert(1)\"/../";
        String s = writeServiceList(base,
                                    new AbstractDestination[] {soapDestination("/SoapContext/GreeterPort")},
                                    new AbstractDestination[] {restDestination("/resources")}, null);
        assertFalse(s, s.contains("\"onmouseover=\""));
        assertTrue(s, s.contains("&quot;onmouseover=&quot;alert(1)&quot;"));
    }

    @Test
    public void testPublishedEndpointUrlEscaped() throws Exception {
        AbstractDestination rest = restDestination("/resources");
        rest.getEndpointInfo().setProperty("publishedEndpointUrl",
                                           "http://localhost:8080/<script>alert(1)</script>");
        String s = writeServiceList(BASE, new AbstractDestination[0], new AbstractDestination[] {rest}, null);
        assertFalse(s, s.contains("<script>"));
        assertTrue(s, s.contains("http://localhost:8080/&lt;script&gt;alert(1)&lt;/script&gt;?_wadl"));
    }

    @Test
    public void testAtomLinkEscaped() throws Exception {
        Map<String, String> atomMap = Collections.singletonMap("/resources", "/atom\"><script>alert(1)</script>");
        String s = writeServiceList(BASE, new AbstractDestination[0],
                                    new AbstractDestination[] {restDestination("/resources")}, atomMap);
        assertTrue(s, s.contains("Atom Log Feed"));
        assertFalse(s, s.contains("<script>"));
        assertTrue(s, s.contains("<a href=\"" + BASE + "/atom&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\">"));
    }

    @Test
    public void testPlainAddressesUnchanged() throws Exception {
        String s = writeServiceList(BASE,
                                    new AbstractDestination[] {soapDestination("/SoapContext/GreeterPort")},
                                    new AbstractDestination[] {restDestination("/resources")}, null);
        assertTrue(s, s.contains("<span class=\"value\">" + BASE + "/SoapContext/GreeterPort</span>"));
        assertTrue(s, s.contains("<a href=\"" + BASE + "/SoapContext/GreeterPort?wsdl\">"));
        assertTrue(s, s.contains("<a href=\"" + BASE + "/resources?_wadl\">" + BASE + "/resources?_wadl</a>"));
    }

    @Test
    public void testWriteServiceList() throws Exception {
        String styleSheetPath = "/app/services/?stylesheet=1";
        FormattedServiceListWriter writer =
                new FormattedServiceListWriter(styleSheetPath,
                        "CXF services", false, null);

        StringWriter sw = new StringWriter();
        writer.writeServiceList(new PrintWriter(sw), "/path", new AbstractDestination[0], new AbstractDestination[0]);

        assertTrue(sw.toString().contains("href=\"" + styleSheetPath + "\""));
    }

    @Test
    public void testStripMultipleForwardSlashes() throws Exception {
        String styleSheetPath = "////app/services/?stylesheet=1";
        FormattedServiceListWriter writer =
                new FormattedServiceListWriter(styleSheetPath,
                        "CXF services", false, null);

        StringWriter sw = new StringWriter();
        writer.writeServiceList(new PrintWriter(sw), "/path", new AbstractDestination[0], new AbstractDestination[0]);

        String desiredStyleSheetPath = "/app/services/?stylesheet=1";
        assertTrue(sw.toString().contains("href=\"" + desiredStyleSheetPath + "\""));
    }

    @Test
    public void testStyleSheetPathEscaped() throws Exception {
        String styleSheetPath = "/app/services/\"><script>alert(1)</script>/?stylesheet=1";
        FormattedServiceListWriter writer =
                new FormattedServiceListWriter(styleSheetPath,
                        "CXF services", false, null);

        StringWriter sw = new StringWriter();
        writer.writeServiceList(new PrintWriter(sw), "/path", new AbstractDestination[0], new AbstractDestination[0]);

        String s = sw.toString();
        assertFalse(s, s.contains("<script>"));
        assertTrue(s, s.contains("href=\"/app/services/&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;/?stylesheet=1\""));
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
