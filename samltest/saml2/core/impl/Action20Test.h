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

class Action20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedNamespace; 
    XMLCh* expectedContent; 

public:
    void setUp() {
        expectedNamespace = XMLString::transcode("urn:string:namespace"); 
        expectedContent = XMLString::transcode("someActionName"); 

        singleElementFile = data_path + "saml2/core/impl/Action.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedNamespace);
        XMLString::release(&expectedContent);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Action* action = dynamic_cast<Action*>(xo.get());
        TS_ASSERT(action!=NULL);

        assertEquals("Element content", expectedContent, action->getAction());
        assertEquals("Namespace attribute", expectedNamespace, action->getNamespace());
    }


    void testSingleElementMarshall() {
        Action* action = ActionBuilder::buildAction();
        TS_ASSERT(action!=NULL);

        action->setAction(expectedContent);
        action->setNamespace(expectedNamespace);
        assertEquals(expectedDOM, action);
    }

};
