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

class Assertion20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    const XMLCh* expectedVersion;
    XMLCh* expectedID;
    DateTime* expectedIssueInstant;

public:
    void setUp() {
        expectedVersion = samlconstants::SAML20_VERSION;
        expectedID = XMLString::transcode("abc123");
        expectedIssueInstant = new DateTime(XMLString::transcode("1984-08-26T10:01:30.043Z"));
        expectedIssueInstant->parseDateTime();
    

        singleElementFile = data_path + "saml2/core/impl/Assertion.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/AssertionOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/AssertionChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        delete expectedIssueInstant;
        XMLString::release(&expectedID);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Assertion* assertion = dynamic_cast<Assertion*>(xo.get());
        TS_ASSERT(assertion!=NULL);

        assertEquals("ID attribute", expectedID, assertion->getID());
        assertEquals("Version attribute", expectedVersion, assertion->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), assertion->getIssueInstant()->getEpoch());

        TS_ASSERT(assertion->getIssuer()==NULL);
        TS_ASSERT(assertion->getSignature()==NULL);
        TS_ASSERT(assertion->getSubject()==NULL);
        TS_ASSERT(assertion->getConditions()==NULL);
        TS_ASSERT(assertion->getAdvice()==NULL);

        TSM_ASSERT_EQUALS("# of Statement child elements", 0, assertion->getStatements().size());
        TSM_ASSERT_EQUALS("# of AuthnStatement child elements", 0, assertion->getAuthnStatements().size());
        TSM_ASSERT_EQUALS("# of AttributeStatement child elements", 0, assertion->getAttributeStatements().size());
        TSM_ASSERT_EQUALS("# of AuthzDecisionStatement child elements", 0, assertion->getAuthzDecisionStatements().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Assertion* assertion= dynamic_cast<Assertion*>(xo.get());
        TS_ASSERT(assertion!=NULL);

        assertEquals("ID attribute", expectedID, assertion->getID());
        assertEquals("Version attribute", expectedVersion, assertion->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), assertion->getIssueInstant()->getEpoch());

        TS_ASSERT(assertion->getIssuer()!=NULL);
        TS_ASSERT(assertion->getSignature()==NULL);
        TS_ASSERT(assertion->getSubject()!=NULL);
        TS_ASSERT(assertion->getConditions()!=NULL);
        TS_ASSERT(assertion->getAdvice()!=NULL);

        TSM_ASSERT_EQUALS("# of Statement child elements", 0, assertion->getStatements().size());
        TSM_ASSERT_EQUALS("# of AuthnStatement child elements", 1, assertion->getAuthnStatements().size());
        TSM_ASSERT_EQUALS("# of AttributeStatement child elements", 3, assertion->getAttributeStatements().size());
        TSM_ASSERT_EQUALS("# of AuthzDecisionStatement child elements", 2, assertion->getAuthzDecisionStatements().size());
    }

    void testSingleElementMarshall() {
        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setID(expectedID);
        assertion->setIssueInstant(expectedIssueInstant);
        assertEquals(expectedDOM, assertion);
    }

    void testChildElementsMarshall() {
        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setID(expectedID);
        assertion->setIssueInstant(expectedIssueInstant);
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
        assertEquals(expectedChildElementsDOM, assertion);

        // Note: assertEquals() above has already 'delete'-ed the XMLObject* it was passed
        assertion=NULL;
        assertion=AssertionBuilder::buildAssertion();
        assertion->setID(expectedID);
        assertion->setIssueInstant(expectedIssueInstant);
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
        assertEquals(expectedChildElementsDOM, assertion);
    }

};
