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
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2;

class NameID20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedNameQualifier; 
    XMLCh* expectedSPNameQualifier; 
    XMLCh* expectedFormat; 
    XMLCh* expectedSPProvidedID; 
    XMLCh* expectedContent; 

public:
    void setUp() {
        expectedNameQualifier = XMLString::transcode("nq"); 
        expectedSPNameQualifier = XMLString::transcode("spnq"); 
        expectedFormat = XMLString::transcode("format"); 
        expectedSPProvidedID = XMLString::transcode("spID"); 
        expectedContent = XMLString::transcode("someNameID"); 

        singleElementFile = data_path + "saml2/core/impl/NameID.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/NameIDOptionalAttributes.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedNameQualifier);
        XMLString::release(&expectedSPNameQualifier);
        XMLString::release(&expectedFormat);
        XMLString::release(&expectedSPProvidedID);
        XMLString::release(&expectedContent);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        NameID* nameid = dynamic_cast<NameID*>(xo.get());
        TS_ASSERT(nameid!=nullptr);

        assertEquals("Element content", expectedContent, nameid->getName());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        NameID* nameid = dynamic_cast<NameID*>(xo.get());
        TS_ASSERT(nameid!=nullptr);

        assertEquals("NameQualifier attribute", expectedNameQualifier, nameid->getNameQualifier());
        assertEquals("SPNameQualifier attribute", expectedSPNameQualifier, nameid->getSPNameQualifier());
        assertEquals("Format attribute", expectedFormat, nameid->getFormat());
        assertEquals("SPProvidedID attribute", expectedSPProvidedID, nameid->getSPProvidedID());
        assertEquals("Element content", expectedContent, nameid->getName());
    }


    void testSingleElementMarshall() {
        NameID* nameid = NameIDBuilder::buildNameID();
        TS_ASSERT(nameid!=nullptr);

        nameid->setName(expectedContent);
        assertEquals(expectedDOM, nameid);
    }

    void testSingleElementOptionalAttributesMarshall() {
        NameID* nameid = NameIDBuilder::buildNameID();
        TS_ASSERT(nameid!=nullptr);

        nameid->setNameQualifier(expectedNameQualifier);
        nameid->setSPNameQualifier(expectedSPNameQualifier);
        nameid->setFormat(expectedFormat);
        nameid->setSPProvidedID(expectedSPProvidedID);
        nameid->setName(expectedContent);
        assertEquals(expectedOptionalAttributesDOM, nameid);
    }

};
