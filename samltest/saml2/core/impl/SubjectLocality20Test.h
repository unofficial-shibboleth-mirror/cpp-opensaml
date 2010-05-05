/*
 *  Copyright 2001-2010 Internet2
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

class SubjectLocality20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedAddress; 
    XMLCh* expectedDNSName; 

public:
    void setUp() {
        expectedAddress = XMLString::transcode("10.1.2.3");; 
        expectedDNSName = XMLString::transcode("client.example.org"); 

        singleElementFile = data_path + "saml2/core/impl/SubjectLocality.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/SubjectLocalityOptionalAttributes.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedAddress);
        XMLString::release(&expectedDNSName);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        SubjectLocality* sl = dynamic_cast<SubjectLocality*>(xo.get());
        TS_ASSERT(sl!=nullptr);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        SubjectLocality* sl = dynamic_cast<SubjectLocality*>(xo.get());
        TS_ASSERT(sl!=nullptr);
        assertEquals("Address attribute", expectedAddress, sl->getAddress());
        assertEquals("DNSName attribute", expectedDNSName, sl->getDNSName());
    }

    void testSingleElementMarshall() {
        SubjectLocality* sl=SubjectLocalityBuilder::buildSubjectLocality();
        assertEquals(expectedDOM, sl);
    }

    void testSingleElementOptionalAttributesMarshall() {
        SubjectLocality* sl=SubjectLocalityBuilder::buildSubjectLocality();
        sl->setAddress(expectedAddress);
        sl->setDNSName(expectedDNSName);
        assertEquals(expectedOptionalAttributesDOM, sl);
    }

};
