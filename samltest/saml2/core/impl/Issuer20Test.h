/*
 *  Copyright 2001-2006 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "internal.h"
#include <saml/saml2/core/Assertions.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2;

class Issuer20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
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
        expectedContent = XMLString::transcode("someIssuer"); 

        singleElementFile = data_path + "saml2/core/impl/Issuer.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/IssuerOptionalAttributes.xml";
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
        Issuer* issuer = dynamic_cast<Issuer*>(xo.get());
        TS_ASSERT(issuer!=NULL);

        assertEquals("Element content", expectedContent, issuer->getName());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Issuer* issuer = dynamic_cast<Issuer*>(xo.get());
        TS_ASSERT(issuer!=NULL);

        assertEquals("NameQualifier attribute", expectedNameQualifier, issuer->getNameQualifier());
        assertEquals("SPNameQualifier attribute", expectedSPNameQualifier, issuer->getSPNameQualifier());
        assertEquals("Format attribute", expectedFormat, issuer->getFormat());
        assertEquals("SPProvidedID attribute", expectedSPProvidedID, issuer->getSPProvidedID());
        assertEquals("Element content", expectedContent, issuer->getName());
    }


    void testSingleElementMarshall() {
        Issuer* issuer = IssuerBuilder::buildIssuer();
        TS_ASSERT(issuer!=NULL);

        issuer->setName(expectedContent);
        assertEquals(expectedDOM, issuer);
    }

    void testSingleElementOptionalAttributesMarshall() {
        Issuer* issuer = IssuerBuilder::buildIssuer();
        TS_ASSERT(issuer!=NULL);

        issuer->setNameQualifier(expectedNameQualifier);
        issuer->setSPNameQualifier(expectedSPNameQualifier);
        issuer->setFormat(expectedFormat);
        issuer->setSPProvidedID(expectedSPProvidedID);
        issuer->setName(expectedContent);
        assertEquals(expectedOptionalAttributesDOM, issuer);
    }

};
