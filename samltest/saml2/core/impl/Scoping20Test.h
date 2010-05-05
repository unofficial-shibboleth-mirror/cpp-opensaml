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
#include <saml/saml2/core/Protocols.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;

class Scoping20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    int expectedProxycount;

public:
    void setUp() {
        expectedProxycount = 5;
        singleElementFile = data_path + "saml2/core/impl/Scoping.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/ScopingOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/ScopingChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Scoping* scoping = dynamic_cast<Scoping*>(xo.get());
        TS_ASSERT(scoping!=nullptr);

        TSM_ASSERT_EQUALS("ProxyCount attribute presence", false, scoping->getProxyCount().first);
        TS_ASSERT(scoping->getIDPList()==nullptr);
        TSM_ASSERT_EQUALS("# of RequesterID child elements", 0, scoping->getRequesterIDs().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Scoping* scoping = dynamic_cast<Scoping*>(xo.get());
        TS_ASSERT(scoping!=nullptr);

        TSM_ASSERT_EQUALS("ProxyCount attribute presence", true, scoping->getProxyCount().first);
        TSM_ASSERT_EQUALS("ProxyCount attribute value", expectedProxycount, scoping->getProxyCount().second);
        TS_ASSERT(scoping->getIDPList()==nullptr);
        TSM_ASSERT_EQUALS("# of RequesterID child elements", 0, scoping->getRequesterIDs().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Scoping* scoping= dynamic_cast<Scoping*>(xo.get());
        TS_ASSERT(scoping!=nullptr);

        TSM_ASSERT_EQUALS("ProxyCount attribute presence", false, scoping->getProxyCount().first);
        TS_ASSERT(scoping->getIDPList()!=nullptr);
        TSM_ASSERT_EQUALS("# of RequesterID child elements", 3, scoping->getRequesterIDs().size());
    }

    void testSingleElementMarshall() {
        Scoping* scoping=ScopingBuilder::buildScoping();
        assertEquals(expectedDOM, scoping);
    }

    void testSingleElementOptionalAttributesMarshall() {
        Scoping* scoping=ScopingBuilder::buildScoping();
        scoping->setProxyCount(expectedProxycount);
        assertEquals(expectedOptionalAttributesDOM, scoping);
    }

    void testChildElementsMarshall() {
        Scoping* scoping=ScopingBuilder::buildScoping();
        scoping->setIDPList(IDPListBuilder::buildIDPList());
        scoping->getRequesterIDs().push_back(RequesterIDBuilder::buildRequesterID());
        scoping->getRequesterIDs().push_back(RequesterIDBuilder::buildRequesterID());
        scoping->getRequesterIDs().push_back(RequesterIDBuilder::buildRequesterID());
        assertEquals(expectedChildElementsDOM, scoping);
    }

};
