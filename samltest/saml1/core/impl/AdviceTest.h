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
#include <saml/saml1/core/Assertions.h>

using namespace opensaml::saml1;

class AdviceTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* AssertionID;
    XMLCh* IssueInstant;

public:
    void setUp() {
        AssertionID=XMLString::transcode("_123456789");
        IssueInstant=XMLString::transcode("1971-03-19T13:23:00Z");
        singleElementFile = data_path + "saml1/core/impl/singleAdvice.xml";
        childElementsFile  = data_path + "saml1/core/impl/AdviceWithChildren.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&AssertionID);
        XMLString::release(&IssueInstant);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Advice* advice = dynamic_cast<Advice*>(xo.get());
        TS_ASSERT(advice!=nullptr);
        TSM_ASSERT_EQUALS("Number of child AssertIDReference elements", 0, advice->getAssertionIDReferences().size());
        TSM_ASSERT_EQUALS("Number of child Assertion elements", 0, advice->getAssertions().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Advice* advice = dynamic_cast<Advice*>(xo.get());
        TSM_ASSERT_EQUALS("Number of child AssertIDReference elements", 2, advice->getAssertionIDReferences().size());
        TSM_ASSERT_EQUALS("Number of child Assertion elements", 1, advice->getAssertions().size());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AdviceBuilder::buildAdvice());
    }

    void testChildElementsMarshall() {
        Advice* advice=AdviceBuilder::buildAdvice();
        
        advice->getAssertionIDReferences().push_back(AssertionIDReferenceBuilder::buildAssertionIDReference());
        Assertion* assertion=AssertionBuilder::buildAssertion();
        assertion->setAssertionID(AssertionID);
        assertion->setIssueInstant(IssueInstant);
        advice->getAssertions().push_back(assertion);
        advice->getAssertionIDReferences().push_back(AssertionIDReferenceBuilder::buildAssertionIDReference());

        assertEquals(expectedChildElementsDOM, advice);
    }

};
