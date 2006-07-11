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

class AssertionTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    int expectedMinorVersion;
    XMLCh* expectedIssuer;
    DateTime* expectedIssueInstant;
    XMLCh* expectedID;

public:
    void setUp() {
        expectedID=XMLString::transcode("ident");
        expectedMinorVersion=1;
        expectedIssueInstant=new DateTime(XMLString::transcode("1970-01-02T01:01:02.100Z"));
        expectedIssueInstant->parseDateTime();
        expectedIssuer=XMLString::transcode("issuer");
        singleElementFile = data_path + "saml1/core/impl/singleAssertion.xml";
        singleElementOptionalAttributesFile = data_path + "saml1/core/impl/singleAssertionAttributes.xml";
        childElementsFile  = data_path + "saml1/core/impl/AssertionWithChildren.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedIssuer);
        delete expectedIssueInstant;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Assertion& assertion = dynamic_cast<Assertion&>(*xo.get());
        TSM_ASSERT("Issuer attribute", assertion.getIssuer()==NULL);
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), assertion.getIssueInstant()->getEpoch());
        assertEquals("ID attribute", expectedID, assertion.getAssertionID());

        TSM_ASSERT("Conditions element", assertion.getConditions()==NULL);
        TSM_ASSERT("Advice element", assertion.getAdvice()==NULL);

        TSM_ASSERT_EQUALS("Statement element count", 0, assertion.getStatements().size());
        TSM_ASSERT_EQUALS("SubjectStatements element count", 0, assertion.getSubjectStatements().size());
        TSM_ASSERT_EQUALS("AttributeStatements element count", 0, assertion.getAttributeStatements().size());
        TSM_ASSERT_EQUALS("AuthenticationStatements element count", 0, assertion.getAuthenticationStatements().size());
        TSM_ASSERT_EQUALS("AuthorizationDecisionStatements element count", 0, assertion.getAuthorizationDecisionStatements().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Assertion& assertion = dynamic_cast<Assertion&>(*xo.get());

        assertEquals("Issuer attribute", expectedIssuer, assertion.getIssuer());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), assertion.getIssueInstant()->getEpoch());
        assertEquals("ID attribute", expectedID, assertion.getAssertionID());
        TSM_ASSERT_EQUALS("Issuer expectedMinorVersion", expectedMinorVersion, assertion.getMinorVersion().second);

        TSM_ASSERT("Conditions element", assertion.getConditions()==NULL);
        TSM_ASSERT("Advice element", assertion.getAdvice()==NULL);

        TSM_ASSERT_EQUALS("Statement element count", 0, assertion.getStatements().size());
        TSM_ASSERT_EQUALS("SubjectStatements element count", 0, assertion.getSubjectStatements().size());
        TSM_ASSERT_EQUALS("AttributeStatements element count", 0, assertion.getAttributeStatements().size());
        TSM_ASSERT_EQUALS("AuthenticationStatements element count", 0, assertion.getAuthenticationStatements().size());
        TSM_ASSERT_EQUALS("AuthorizationDecisionStatements element count", 0, assertion.getAuthorizationDecisionStatements().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Assertion& assertion = dynamic_cast<Assertion&>(*xo.get());

        TSM_ASSERT("Issuer attribute", assertion.getIssuer()==NULL);
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), assertion.getIssueInstant()->getEpoch());
        assertEquals("ID attribute", expectedID, assertion.getAssertionID());

        TSM_ASSERT("Conditions element null", assertion.getConditions()!=NULL);
        TSM_ASSERT("Advice element null", assertion.getAdvice()!=NULL);

        TSM_ASSERT_EQUALS("AuthenticationStatements element count", 2, assertion.getAuthenticationStatements().size());
        TSM_ASSERT_EQUALS("AttributeStatements element count", 3, assertion.getAttributeStatements().size());
        TSM_ASSERT_EQUALS("AuthorizationDecisionStatements element count", 3, assertion.getAuthorizationDecisionStatements().size());
    }

    void testSingleElementMarshall() {
        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setAssertionID(expectedID);
        assertion->setIssueInstant(expectedIssueInstant);
        assertEquals(expectedDOM, assertion);
    }

    void testSingleElementOptionalAttributesMarshall() {
        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setIssueInstant(expectedIssueInstant);
        assertion->setAssertionID(expectedID);
        assertion->setIssuer(expectedIssuer);
        assertEquals(expectedOptionalAttributesDOM, assertion);
    }

    void testChildElementsMarshall() {
        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setIssueInstant(expectedIssueInstant);
        assertion->setAssertionID(expectedID);
        assertion->setConditions(ConditionsBuilder::buildConditions());
        assertion->setAdvice(AdviceBuilder::buildAdvice());
        assertion->getAuthenticationStatements().push_back(
            AuthenticationStatementBuilder::buildAuthenticationStatement()
            );
        assertion->getAuthorizationDecisionStatements().push_back(
            AuthorizationDecisionStatementBuilder::buildAuthorizationDecisionStatement()
            );
        assertion->getAttributeStatements().push_back(
            AttributeStatementBuilder::buildAttributeStatement()
            );
        assertion->getAuthenticationStatements().push_back(
            AuthenticationStatementBuilder::buildAuthenticationStatement()
            );
        assertion->getAuthorizationDecisionStatements().push_back(
            AuthorizationDecisionStatementBuilder::buildAuthorizationDecisionStatement()
            );
        assertion->getAttributeStatements().push_back(
            AttributeStatementBuilder::buildAttributeStatement()
            );
        assertion->getAuthorizationDecisionStatements().push_back(
            AuthorizationDecisionStatementBuilder::buildAuthorizationDecisionStatement()
            );
        assertion->getAttributeStatements().push_back(
            AttributeStatementBuilder::buildAttributeStatement()
            );
        assertEquals(expectedChildElementsDOM, assertion);
    }

};
