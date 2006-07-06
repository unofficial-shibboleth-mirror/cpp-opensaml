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
#include <saml/saml2/core/Protocols.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;

class NameIDPolicy20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedFormat; 
    XMLCh* expectedSPNameQualifier; 
    bool expectedAllowCreate;

public:
    void setUp() {
        expectedFormat = XMLString::transcode("urn:string:format");; 
        expectedSPNameQualifier = XMLString::transcode("urn:string:spname"); 
        expectedAllowCreate=true;

        singleElementFile = data_path + "saml2/core/impl/NameIDPolicy.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/NameIDPolicyOptionalAttributes.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedFormat);
        XMLString::release(&expectedSPNameQualifier);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        NameIDPolicy* policy = dynamic_cast<NameIDPolicy*>(xo.get());
        TS_ASSERT(policy!=NULL);
        TSM_ASSERT_EQUALS("AllowCreate attribute presence", false, policy->AllowCreate().first);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        NameIDPolicy* policy = dynamic_cast<NameIDPolicy*>(xo.get());
        TS_ASSERT(policy!=NULL);
        assertEquals("Format attribute", expectedFormat, policy->getFormat());
        assertEquals("SPNameQualifier attribute", expectedSPNameQualifier, policy->getSPNameQualifier());
        TSM_ASSERT_EQUALS("AllowCreate attribute presence", true, policy->AllowCreate().first);
        TSM_ASSERT_EQUALS("AllowCreate attribute value", expectedAllowCreate, policy->AllowCreate().second);
    }

    void testSingleElementMarshall() {
        NameIDPolicy* policy=NameIDPolicyBuilder::buildNameIDPolicy();
        assertEquals(expectedDOM, policy);
    }

    void testSingleElementOptionalAttributesMarshall() {
        NameIDPolicy* policy=NameIDPolicyBuilder::buildNameIDPolicy();
        policy->setFormat(expectedFormat);
        policy->setSPNameQualifier(expectedSPNameQualifier);
        policy->AllowCreate(expectedAllowCreate);
        assertEquals(expectedOptionalAttributesDOM, policy);
    }

};
