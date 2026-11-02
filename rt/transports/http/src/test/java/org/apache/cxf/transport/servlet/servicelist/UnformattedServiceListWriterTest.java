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
import java.util.logging.Logger;

import org.apache.cxf.message.Message;
import org.apache.cxf.service.model.EndpointInfo;
import org.apache.cxf.transport.AbstractDestination;
import org.apache.cxf.transport.Conduit;

import org.junit.Assert;
import org.junit.Test;

public class UnformattedServiceListWriterTest extends Assert {
    private static final String BASE = "http://localhost:8080/service_listing/services";
    private static final String SCRIPT_BASE = BASE + "/<script>alert(1)</script>/../../";
    private static final String ESCAPED_SCRIPT_BASE =
        BASE + "/&lt;script&gt;alert(1)&lt;/script&gt;/../../";

    private static String writeServiceList(boolean renderWsdlList,
                                           String basePath,
                                           AbstractDestination[] soap,
                                           AbstractDestination[] rest) throws Exception {
        StringWriter out = new StringWriter();
        PrintWriter pw = new PrintWriter(out);
        new UnformattedServiceListWriter(renderWsdlList).writeServiceList(pw, basePath, soap, rest);
        pw.flush();
        return out.toString();
    }

    private static AbstractDestination destination(String address) {
        EndpointInfo ei = new EndpointInfo();
        ei.setAddress(address);
        return new TestDestination(ei);
    }

    @Test
    public void testSoapEndpointAddressEscaped() throws Exception {
        String s = writeServiceList(true, SCRIPT_BASE,
                                    new AbstractDestination[] {destination("/SoapContext/GreeterPort")},
                                    new AbstractDestination[0]);
        assertFalse(s, s.contains("<script>"));
        assertTrue(s, s.contains(ESCAPED_SCRIPT_BASE + "/SoapContext/GreeterPort?wsdl\n"));
    }

    @Test
    public void testRestEndpointAddressEscaped() throws Exception {
        String s = writeServiceList(false, SCRIPT_BASE, new AbstractDestination[0],
                                    new AbstractDestination[] {destination("/resources")});
        assertFalse(s, s.contains("<script>"));
        assertTrue(s, s.contains(ESCAPED_SCRIPT_BASE + "/resources?_wadl\n"));
    }

    @Test
    public void testEndpointAddressQuotesEscaped() throws Exception {
        String base = BASE + "/\"><img src=x onerror=alert(1)>/../";
        String s = writeServiceList(false, base,
                                    new AbstractDestination[] {destination("/SoapContext/GreeterPort")},
                                    new AbstractDestination[] {destination("/resources")});
        assertFalse(s, s.contains("<img"));
        assertFalse(s, s.contains("\">"));
        assertTrue(s, s.contains(BASE + "/&quot;&gt;&lt;img src=x onerror=alert(1)&gt;/..//resources?_wadl"));
    }

    @Test
    public void testPlainAddressesUnchanged() throws Exception {
        String s = writeServiceList(true, BASE,
                                    new AbstractDestination[] {destination("/SoapContext/GreeterPort")},
                                    new AbstractDestination[] {destination("/resources")});
        assertTrue(s, s.contains(BASE + "/SoapContext/GreeterPort?wsdl\n"));
        assertTrue(s, s.contains(BASE + "/resources?_wadl\n"));
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
