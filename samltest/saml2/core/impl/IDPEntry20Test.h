/*
 *  Copyright 2001-2007 Internet2
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
#include <saml/saml2/core/Protocols.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;

class IDPEntry20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedProviderID; 
    XMLCh* expectedName; 
    XMLCh* expectedLoc;

public:
    void setUp() {
        expectedProviderID = XMLString::transcode("urn:string:providerid");; 
        expectedName = XMLString::transcode("Example IdP"); 
        expectedLoc = XMLString::transcode("http://idp.example.org/endpoint"); 

        singleElementFile = data_path + "saml2/core/impl/IDPEntry.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/IDPEntryOptionalAttributes.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedProviderID);
        XMLString::release(&expectedName);
        XMLString::release(&expectedLoc);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        IDPEntry* entry = dynamic_cast<IDPEntry*>(xo.get());
        TS_ASSERT(entry!=NULL);
        assertEquals("ProviderID attribute", expectedProviderID, entry->getProviderID());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        IDPEntry* entry = dynamic_cast<IDPEntry*>(xo.get());
        TS_ASSERT(entry!=NULL);
        assertEquals("ProviderID attribute", expectedProviderID, entry->getProviderID());
        assertEquals("Name attribute", expectedName, entry->getName());
        assertEquals("Loc attribute", expectedLoc, entry->getLoc());
    }

    void testSingleElementMarshall() {
        IDPEntry* entry=IDPEntryBuilder::buildIDPEntry();
        entry->setProviderID(expectedProviderID);
        assertEquals(expectedDOM, entry);
    }

    void testSingleElementOptionalAttributesMarshall() {
        IDPEntry* entry=IDPEntryBuilder::buildIDPEntry();
        entry->setProviderID(expectedProviderID);
        entry->setName(expectedName);
        entry->setLoc(expectedLoc);
        assertEquals(expectedOptionalAttributesDOM, entry);
    }

};
