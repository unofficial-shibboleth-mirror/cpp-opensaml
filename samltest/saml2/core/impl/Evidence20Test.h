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

class Evidence20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/Evidence.xml";
        childElementsFile  = data_path + "saml2/core/impl/EvidenceChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Evidence* evidence = dynamic_cast<Evidence*>(xo.get());
        TS_ASSERT(evidence!=NULL);

        TSM_ASSERT_EQUALS("# of AssertionIDRef child elements", 0, evidence->getAssertionIDRefs().size());
        TSM_ASSERT_EQUALS("# of AssertionURIRef child elements", 0, evidence->getAssertionURIRefs().size());
        TSM_ASSERT_EQUALS("# of Assertion child elements", 0, evidence->getAssertions().size());
        TSM_ASSERT_EQUALS("# of EncryptedAssertion child elements", 0, evidence->getEncryptedAssertions().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Evidence* evidence= dynamic_cast<Evidence*>(xo.get());
        TS_ASSERT(evidence!=NULL);

        TSM_ASSERT_EQUALS("# of AssertionIDRef child elements", 3, evidence->getAssertionIDRefs().size());
        TSM_ASSERT_EQUALS("# of AssertionURIRef child elements", 2, evidence->getAssertionURIRefs().size());
        TSM_ASSERT_EQUALS("# of Assertion child elements", 2, evidence->getAssertions().size());
        TSM_ASSERT_EQUALS("# of EncryptedAssertion child elements", 1, evidence->getEncryptedAssertions().size());
    }

    void testSingleElementMarshall() {
        Evidence* evidence=EvidenceBuilder::buildEvidence();
        assertEquals(expectedDOM, evidence);
    }

    void testChildElementsMarshall() {
        Evidence* evidence=EvidenceBuilder::buildEvidence();

        Assertion* assertion1 = AssertionBuilder::buildAssertion();
        assertion1->setID(XMLString::transcode("abc123"));
        assertion1->setIssueInstant(new DateTime(XMLString::transcode("2006-07-21T22:27:19Z")));

        Assertion* assertion2 = AssertionBuilder::buildAssertion();
        assertion2->setID(XMLString::transcode("def456"));
        assertion2->setIssueInstant(new DateTime(XMLString::transcode("2006-07-21T22:27:19Z")));

        evidence->getAssertionIDRefs().push_back(AssertionIDRefBuilder::buildAssertionIDRef());
        evidence->getAssertionIDRefs().push_back(AssertionIDRefBuilder::buildAssertionIDRef());
        evidence->getAssertionURIRefs().push_back(AssertionURIRefBuilder::buildAssertionURIRef());
        evidence->getAssertionIDRefs().push_back(AssertionIDRefBuilder::buildAssertionIDRef());
        evidence->getAssertionURIRefs().push_back(AssertionURIRefBuilder::buildAssertionURIRef());
        evidence->getAssertions().push_back(assertion1);
        evidence->getEncryptedAssertions().push_back(EncryptedAssertionBuilder::buildEncryptedAssertion());
        evidence->getAssertions().push_back(assertion2);
        assertEquals(expectedChildElementsDOM, evidence);
    }

};
