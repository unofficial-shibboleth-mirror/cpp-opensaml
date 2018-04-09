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

class Assertion20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    const XMLCh* expectedVersion;
    XMLCh* expectedID;
    scoped_ptr<XMLDateTime> expectedIssueInstant;

public:
    void setUp() {
        expectedVersion = samlconstants::SAML20_VERSION;
        expectedID = XMLString::transcode("abc123");
        expectedIssueInstant.reset(new XMLDateTime(XMLString::transcode("1984-08-26T10:01:30.043Z")));
        expectedIssueInstant->parseDateTime();

        singleElementFile = data_path + "saml2/core/impl/Assertion.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/AssertionOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/AssertionChildElements.xml";
        SAMLObjectBaseTestCase::setUp();
    }

    void tearDown() {
        expectedIssueInstant.reset();
        XMLString::release(&expectedID);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Assertion* assertion = dynamic_cast<Assertion*>(xo.get());
        TS_ASSERT(assertion!=nullptr);

        assertEquals("ID attribute", expectedID, assertion->getID());
        assertEquals("Version attribute", expectedVersion, assertion->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), assertion->getIssueInstant()->getEpoch());

        TS_ASSERT(assertion->getIssuer()==nullptr);
        TS_ASSERT(assertion->getSignature()==nullptr);
        TS_ASSERT(assertion->getSubject()==nullptr);
        TS_ASSERT(assertion->getConditions()==nullptr);
        TS_ASSERT(assertion->getAdvice()==nullptr);

        TSM_ASSERT_EQUALS("# of Statement child elements", 0, assertion->getStatements().size());
        TSM_ASSERT_EQUALS("# of AuthnStatement child elements", 0, assertion->getAuthnStatements().size());
        TSM_ASSERT_EQUALS("# of AttributeStatement child elements", 0, assertion->getAttributeStatements().size());
        TSM_ASSERT_EQUALS("# of AuthzDecisionStatement child elements", 0, assertion->getAuthzDecisionStatements().size());
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Assertion* assertion= dynamic_cast<Assertion*>(xo.get());
        TS_ASSERT(assertion!=nullptr);

        assertEquals("ID attribute", expectedID, assertion->getID());
        assertEquals("Version attribute", expectedVersion, assertion->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), assertion->getIssueInstant()->getEpoch());

        TS_ASSERT(assertion->getIssuer()!=nullptr);
        TS_ASSERT(assertion->getSignature()==nullptr);
        TS_ASSERT(assertion->getSubject()!=nullptr);
        TS_ASSERT(assertion->getConditions()!=nullptr);
        TS_ASSERT(assertion->getAdvice()!=nullptr);

        TSM_ASSERT_EQUALS("# of Statement child elements", 1, assertion->getStatements().size());
        TSM_ASSERT_EQUALS("# of AuthnStatement child elements", 1, assertion->getAuthnStatements().size());
        TSM_ASSERT_EQUALS("# of AttributeStatement child elements", 3, assertion->getAttributeStatements().size());
        TSM_ASSERT_EQUALS("# of AuthzDecisionStatement child elements", 2, assertion->getAuthzDecisionStatements().size());
    }

    void testSingleElementMarshall() {
        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setID(expectedID);
        assertion->setIssueInstant(expectedIssueInstant.get());
        assertEquals(expectedDOM, assertion);
    }

    void testChildElementsMarshall() {
        xmltooling::QName qext("http://www.opensaml.org/", "Foo", "ext");

        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setID(expectedID);
        assertion->setIssueInstant(expectedIssueInstant.get());
        assertion->setIssuer(IssuerBuilder::buildIssuer());
        assertion->setSubject(SubjectBuilder::buildSubject());
        assertion->setConditions(ConditionsBuilder::buildConditions());
        assertion->setAdvice(AdviceBuilder::buildAdvice());

        //Test storing children as their direct type
        assertion->getAuthnStatements().push_back(AuthnStatementBuilder::buildAuthnStatement());
        assertion->getAttributeStatements().push_back(AttributeStatementBuilder::buildAttributeStatement());
        assertion->getAttributeStatements().push_back(AttributeStatementBuilder::buildAttributeStatement());
        assertion->getAuthzDecisionStatements().push_back(AuthzDecisionStatementBuilder::buildAuthzDecisionStatement());
        assertion->getAuthzDecisionStatements().push_back(AuthzDecisionStatementBuilder::buildAuthzDecisionStatement());
        assertion->getAttributeStatements().push_back(AttributeStatementBuilder::buildAttributeStatement());
        assertion->getStatements().push_back(StatementBuilder::buildStatement(qext));
        assertEquals(expectedChildElementsDOM, assertion);

        // Note: assertEquals() above has already 'delete'-ed the XMLObject* it was passed
        assertion=nullptr;
        assertion=AssertionBuilder::buildAssertion();
        assertion->setID(expectedID);
        assertion->setIssueInstant(expectedIssueInstant.get());
        assertion->setIssuer(IssuerBuilder::buildIssuer());
        assertion->setSubject(SubjectBuilder::buildSubject());
        assertion->setConditions(ConditionsBuilder::buildConditions());
        assertion->setAdvice(AdviceBuilder::buildAdvice());

        //Test storing children as a Statement (each is a derived type of StatementAbstractType)
        assertion->getStatements().push_back(AuthnStatementBuilder::buildAuthnStatement());
        assertion->getStatements().push_back(AttributeStatementBuilder::buildAttributeStatement());
        assertion->getStatements().push_back(AttributeStatementBuilder::buildAttributeStatement());
        assertion->getStatements().push_back(AuthzDecisionStatementBuilder::buildAuthzDecisionStatement());
        assertion->getStatements().push_back(AuthzDecisionStatementBuilder::buildAuthzDecisionStatement());
        assertion->getStatements().push_back(AttributeStatementBuilder::buildAttributeStatement());
        assertion->getStatements().push_back(StatementBuilder::buildStatement(qext));
        assertEquals(expectedChildElementsDOM, assertion);
    }

};
