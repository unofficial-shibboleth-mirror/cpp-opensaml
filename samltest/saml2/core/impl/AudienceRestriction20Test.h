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

class AudienceRestriction20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/AudienceRestriction.xml";
        childElementsFile  = data_path + "saml2/core/impl/AudienceRestrictionChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AudienceRestriction* ar = dynamic_cast<AudienceRestriction*>(xo.get());
        TS_ASSERT(ar!=NULL);

        TSM_ASSERT_EQUALS("# of Audience child elements", 0, ar->getAudiences().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AudienceRestriction* ar= dynamic_cast<AudienceRestriction*>(xo.get());
        TS_ASSERT(ar!=NULL);

        TSM_ASSERT_EQUALS("# of Audience child elements", 2, ar->getAudiences().size());
    }

    void testSingleElementMarshall() {
        AudienceRestriction* ar=AudienceRestrictionBuilder::buildAudienceRestriction();
        assertEquals(expectedDOM, ar);
    }

    void testChildElementsMarshall() {
        AudienceRestriction* ar=AudienceRestrictionBuilder::buildAudienceRestriction();
        ar->getAudiences().push_back(AudienceBuilder::buildAudience());
        ar->getAudiences().push_back(AudienceBuilder::buildAudience());
        assertEquals(expectedChildElementsDOM, ar);
    }

};
