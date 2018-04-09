/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

#include "internal.h"
#include <saml/saml2/core/Assertions.h>

using namespace opensaml::saml2;

class AssertionURIRef20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedContent;

public:
    void setUp() {
        expectedContent=XMLString::transcode("assertion URI");
        singleElementFile = data_path + "saml2/core/impl/AssertionURIRef.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedContent);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AssertionURIRef* uriref = dynamic_cast<AssertionURIRef*>(xo.get());
        TS_ASSERT(uriref!=nullptr);
        assertEquals("AssertionURIRef text content", expectedContent, uriref->getAssertionURI());
    }

    void testSingleElementMarshall() {
        AssertionURIRef * uriref = AssertionURIRefBuilder::buildAssertionURIRef();
        uriref->setAssertionURI(expectedContent);
        assertEquals(expectedDOM, uriref);
    }

};
