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

class ProxyRestriction20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    int expectedCount;

public:
    void setUp() {
        expectedCount = 5;
        singleElementFile = data_path + "saml2/core/impl/ProxyRestriction.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/ProxyRestrictionOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/ProxyRestrictionChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        ProxyRestriction* pr = dynamic_cast<ProxyRestriction*>(xo.get());
        TS_ASSERT(pr!=NULL);

        TSM_ASSERT_EQUALS("Count attribute presence", false, pr->getCount().first);
        TSM_ASSERT_EQUALS("# of Audience child elements", 0, pr->getAudiences().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        ProxyRestriction* pr = dynamic_cast<ProxyRestriction*>(xo.get());
        TS_ASSERT(pr!=NULL);

        TSM_ASSERT_EQUALS("Count attribute presence", true, pr->getCount().first);
        TSM_ASSERT_EQUALS("Count attribute value", expectedCount, pr->getCount().second);
        TSM_ASSERT_EQUALS("# of Audience child elements", 0, pr->getAudiences().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        ProxyRestriction* pr= dynamic_cast<ProxyRestriction*>(xo.get());
        TS_ASSERT(pr!=NULL);

        TSM_ASSERT_EQUALS("Count attribute presence", false, pr->getCount().first);
        TSM_ASSERT_EQUALS("# of Audience child elements", 2, pr->getAudiences().size());
    }

    void testSingleElementMarshall() {
        ProxyRestriction* pr=ProxyRestrictionBuilder::buildProxyRestriction();
        assertEquals(expectedDOM, pr);
    }

    void testSingleElementOptionalAttributesMarshall() {
        ProxyRestriction* pr=ProxyRestrictionBuilder::buildProxyRestriction();
        pr->setCount(expectedCount);
        assertEquals(expectedOptionalAttributesDOM, pr);
    }

    void testChildElementsMarshall() {
        ProxyRestriction* pr=ProxyRestrictionBuilder::buildProxyRestriction();
        pr->getAudiences().push_back(AudienceBuilder::buildAudience());
        pr->getAudiences().push_back(AudienceBuilder::buildAudience());
        assertEquals(expectedChildElementsDOM, pr);
    }

};
