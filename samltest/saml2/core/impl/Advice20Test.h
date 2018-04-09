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

class Advice20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

//TODO test with some non-SAML Other children

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/Advice.xml";
        childElementsFile  = data_path + "saml2/core/impl/AdviceChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Advice* advice = dynamic_cast<Advice*>(xo.get());
        TS_ASSERT(advice!=nullptr);

        TSM_ASSERT_EQUALS("# of AssertionIDRef child elements", 0, advice->getAssertionIDRefs().size());
        TSM_ASSERT_EQUALS("# of AssertionURIRef child elements", 0, advice->getAssertionURIRefs().size());
        TSM_ASSERT_EQUALS("# of Assertion child elements", 0, advice->getAssertions().size());
        TSM_ASSERT_EQUALS("# of EncryptedAssertion child elements", 0, advice->getEncryptedAssertions().size());
        TSM_ASSERT_EQUALS("# of Other child elements", 0, advice->getUnknownXMLObjects().size());
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Advice* advice= dynamic_cast<Advice*>(xo.get());
        TS_ASSERT(advice!=nullptr);

        TSM_ASSERT_EQUALS("# of AssertionIDRef child elements", 3, advice->getAssertionIDRefs().size());
        TSM_ASSERT_EQUALS("# of AssertionURIRef child elements", 2, advice->getAssertionURIRefs().size());
        TSM_ASSERT_EQUALS("# of Assertion child elements", 2, advice->getAssertions().size());
        TSM_ASSERT_EQUALS("# of EncryptedAssertion child elements", 1, advice->getEncryptedAssertions().size());
        TSM_ASSERT_EQUALS("# of Other child elements", 0, advice->getUnknownXMLObjects().size());
    }

    void testSingleElementMarshall() {
        Advice* advice=AdviceBuilder::buildAdvice();
        assertEquals(expectedDOM, advice);
    }

    void testChildElementsMarshall() {
        Advice* advice=AdviceBuilder::buildAdvice();

        Assertion* assertion1 = AssertionBuilder::buildAssertion();
        assertion1->setID(XMLString::transcode("abc123"));
        assertion1->setIssueInstant(new XMLDateTime(XMLString::transcode("2006-07-21T22:27:19Z")));

        Assertion* assertion2 = AssertionBuilder::buildAssertion();
        assertion2->setID(XMLString::transcode("def456"));
        assertion2->setIssueInstant(new XMLDateTime(XMLString::transcode("2006-07-21T22:27:19Z")));

        advice->getAssertionIDRefs().push_back(AssertionIDRefBuilder::buildAssertionIDRef());
        advice->getAssertionIDRefs().push_back(AssertionIDRefBuilder::buildAssertionIDRef());
        advice->getAssertionURIRefs().push_back(AssertionURIRefBuilder::buildAssertionURIRef());
        advice->getAssertionIDRefs().push_back(AssertionIDRefBuilder::buildAssertionIDRef());
        advice->getAssertionURIRefs().push_back(AssertionURIRefBuilder::buildAssertionURIRef());
        advice->getAssertions().push_back(assertion1);
        advice->getEncryptedAssertions().push_back(EncryptedAssertionBuilder::buildEncryptedAssertion());
        advice->getAssertions().push_back(assertion2);
        assertEquals(expectedChildElementsDOM, advice);
    }

};
