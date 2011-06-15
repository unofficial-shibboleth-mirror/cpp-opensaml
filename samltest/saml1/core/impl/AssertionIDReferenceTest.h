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
#include <saml/saml1/core/Assertions.h>

using namespace opensaml::saml1;

class AssertionIDReferenceTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedNCName;

public:
    void setUp() {
        singleElementFile = data_path + "saml1/core/impl/singleAssertionIDReference.xml";
        singleElementOptionalAttributesFile  = data_path + "saml1/core/impl/singleAssertionIDReferenceContents.xml";    
        expectedNCName = XMLString::transcode("NibbleAHappyWarthog");
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedNCName);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AssertionIDReference* assertionIDReference = dynamic_cast<AssertionIDReference*>(xo.get());
        TS_ASSERT(assertionIDReference!=nullptr);
        TSM_ASSERT("NCName present", assertionIDReference->getAssertionID()==nullptr);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        AssertionIDReference* assertionIDReference = dynamic_cast<AssertionIDReference*>(xo.get());
        assertEquals("NCName ", expectedNCName, assertionIDReference->getAssertionID());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AssertionIDReferenceBuilder::buildAssertionIDReference());
    }

    void testSingleElementOptionalAttributesMarshall() {
        AssertionIDReference* assertionIDReference=AssertionIDReferenceBuilder::buildAssertionIDReference();
        assertionIDReference->setAssertionID(expectedNCName);
        assertEquals(expectedOptionalAttributesDOM, assertionIDReference);
    }

};
