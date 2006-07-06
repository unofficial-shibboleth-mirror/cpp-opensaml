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
#include <saml/saml2/core/Protocols.h>

using namespace opensaml::saml2p;

class StatusDetail20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/StatusDetail.xml";
        childElementsFile  = data_path + "saml2/core/impl/StatusDetailChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        StatusDetail* sd= dynamic_cast<StatusDetail*>(xo.get());
        TS_ASSERT(sd!=NULL);
        TSM_ASSERT_EQUALS("StatusDetail child elements", sd->getDetails().size(), 0);
    }

    //TODO test with some XMLObject child elements from another namespace
    void IGNOREtestChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        StatusDetail* sd= dynamic_cast<StatusDetail*>(xo.get());
        TS_ASSERT(sd!=NULL);
        TSM_ASSERT_EQUALS("StatusDetail child elements", sd->getDetails().size(), 3);
    }

    void testSingleElementMarshall() {
        StatusDetail* sd=StatusDetailBuilder::buildStatusDetail();
        assertEquals(expectedDOM, sd);
    }

    //TODO test with some XMLObject child elements from another namespace
    void IGNOREtestChildElementsMarshall() {
        StatusDetail* sd=StatusDetailBuilder::buildStatusDetail();
        assertEquals(expectedChildElementsDOM, sd);
    }

};
