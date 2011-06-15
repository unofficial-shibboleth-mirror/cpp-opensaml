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

class ActionTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedContents;
    XMLCh* expectedNamespace;

public:
    void setUp() {
        singleElementFile = data_path + "saml1/core/impl/singleAction.xml";
        singleElementOptionalAttributesFile  = data_path + "saml1/core/impl/singleActionAttributes.xml";    
        expectedContents = XMLString::transcode("Action Contents");
        expectedNamespace = XMLString::transcode("namespace");
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedContents);
        XMLString::release(&expectedNamespace);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Action* action = dynamic_cast<Action*>(xo.get());
        TS_ASSERT(action!=nullptr);
        TSM_ASSERT("namespace attribute present", action->getNamespace()==nullptr);
        TSM_ASSERT("Contents present", action->getAction()==nullptr);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Action* action = dynamic_cast<Action*>(xo.get());
        assertEquals("namespace attribute ", expectedNamespace, action->getNamespace());
        assertEquals("Contents ", expectedContents, action->getAction());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, ActionBuilder::buildAction());
    }

    void testSingleElementOptionalAttributesMarshall() {
        Action* action=ActionBuilder::buildAction();
        action->setNamespace(expectedNamespace);
        action->setAction(expectedContents);
        assertEquals(expectedOptionalAttributesDOM, action);
    }

};
