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
#include <saml/saml1/core/Assertions.h>

using namespace opensaml::saml1;

class ActionTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedContents;
    XMLCh* expectedNamespace;
    QName* qname;

public:
    void setUp() {
        singleElementFile = data_path + "saml1/core/impl/singleAction.xml";
        singleElementOptionalAttributesFile  = data_path + "saml1/core/impl/singleActionAttributes.xml";    
        expectedContents = XMLString::transcode("Action Contents");
        expectedNamespace = XMLString::transcode("namespace");
        qname = new QName(SAMLConstants::SAML1_NS, Action::LOCAL_NAME, SAMLConstants::SAML1_PREFIX);
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        delete qname;
        XMLString::release(&expectedContents);
        XMLString::release(&expectedNamespace);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Action* action = dynamic_cast<Action*>(xo.get());
        TS_ASSERT(action!=NULL);
        TSM_ASSERT("namespace attribute present", action->getNamespace()==NULL);
        TSM_ASSERT("Contents present", action->getValue()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Action* action = dynamic_cast<Action*>(xo.get());
        TSM_ASSERT_SAME_DATA("namespace attribute ", expectedNamespace, action->getNamespace(), XMLString::stringLen(expectedNamespace));
        TSM_ASSERT_SAME_DATA("Contents ", expectedContents, action->getValue(), XMLString::stringLen(expectedContents));
    }

    void testSingleElementMarshall() {
        auto_ptr<Action> action(ActionBuilder::buildAction());
        assertEquals(expectedDOM, action.get());
    }

    void testSingleElementOptionalAttributesMarshall() {
        auto_ptr<Action> action(ActionBuilder::buildAction());
        action->setNamespace(expectedNamespace);
        action->setValue(expectedContents);
        assertEquals(expectedOptionalAttributesDOM, action.get());
    }

};
