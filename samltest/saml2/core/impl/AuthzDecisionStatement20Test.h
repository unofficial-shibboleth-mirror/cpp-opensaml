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

class AuthzDecisionStatement20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedResource; 
    const XMLCh* expectedDecision; 

public:
    void setUp() {
        expectedResource = XMLString::transcode("urn:string:resource"); 
        expectedDecision = AuthzDecisionStatement::DECISION_PERMIT;

        singleElementFile = data_path + "saml2/core/impl/AuthzDecisionStatement.xml";
        childElementsFile  = data_path + "saml2/core/impl/AuthzDecisionStatementChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedResource);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AuthzDecisionStatement* statement = dynamic_cast<AuthzDecisionStatement*>(xo.get());
        TS_ASSERT(statement!=nullptr);

        assertEquals("Resource attribute", expectedResource, statement->getResource());
        assertEquals("Decision attribute", expectedDecision, statement->getDecision());

        TSM_ASSERT_EQUALS("# of Action child elements", 0, statement->getActions().size());
        TS_ASSERT(statement->getEvidence()==nullptr);
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AuthzDecisionStatement* statement= dynamic_cast<AuthzDecisionStatement*>(xo.get());
        TS_ASSERT(statement!=nullptr);

        assertEquals("Resource attribute", nullptr, statement->getResource());
        assertEquals("Decision attribute", nullptr, statement->getDecision());

        TSM_ASSERT_EQUALS("# of Action child elements", 3, statement->getActions().size());
        TS_ASSERT(statement->getEvidence()!=nullptr);
    }

    void testSingleElementMarshall() {
        AuthzDecisionStatement* statement=AuthzDecisionStatementBuilder::buildAuthzDecisionStatement();
        statement->setResource(expectedResource);
        statement->setDecision(expectedDecision);
        assertEquals(expectedDOM, statement);
    }

    void testChildElementsMarshall() {
        AuthzDecisionStatement* statement=AuthzDecisionStatementBuilder::buildAuthzDecisionStatement();
        statement->getActions().push_back(ActionBuilder::buildAction());
        statement->getActions().push_back(ActionBuilder::buildAction());
        statement->getActions().push_back(ActionBuilder::buildAction());
        statement->setEvidence(EvidenceBuilder::buildEvidence());
        assertEquals(expectedChildElementsDOM, statement);
    }

};
