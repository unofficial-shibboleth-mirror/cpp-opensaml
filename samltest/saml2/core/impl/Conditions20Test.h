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

class Conditions20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    DateTime* expectedNotBefore;
    DateTime* expectedNotOnOrAfter;

public:
    void setUp() {
        expectedNotBefore = new DateTime(XMLString::transcode("1984-08-26T10:01:30.043Z"));
        expectedNotBefore->parseDateTime();
        expectedNotOnOrAfter = new DateTime(XMLString::transcode("1984-08-26T10:11:30.043Z"));
        expectedNotOnOrAfter->parseDateTime();

        singleElementFile = data_path + "saml2/core/impl/Conditions.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/ConditionsOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/ConditionsChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        delete expectedNotBefore;
        delete expectedNotOnOrAfter;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Conditions* conditions = dynamic_cast<Conditions*>(xo.get());
        TS_ASSERT(conditions!=NULL);


        TS_ASSERT(conditions->getNotBefore()==NULL);
        TS_ASSERT(conditions->getNotOnOrAfter()==NULL);

        TSM_ASSERT_EQUALS("# of Condition child elements", 0, conditions->getConditions().size());
        TSM_ASSERT_EQUALS("# of AudienceRestriction child elements", 0, conditions->getAudienceRestrictions().size());
        TSM_ASSERT_EQUALS("# of OneTimeUse child elements", 0, conditions->getOneTimeUses().size());
        TSM_ASSERT_EQUALS("# of ProxyRestriction child elements", 0, conditions->getProxyRestrictions().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Conditions* conditions = dynamic_cast<Conditions*>(xo.get());
        TS_ASSERT(conditions!=NULL);

        TSM_ASSERT_EQUALS("NotBefore attribute", expectedNotBefore->getEpoch(), conditions->getNotBefore()->getEpoch());
        TSM_ASSERT_EQUALS("NotOnOrAfter attribute", expectedNotOnOrAfter->getEpoch(), conditions->getNotOnOrAfter()->getEpoch());

        TSM_ASSERT_EQUALS("# of Condition child elements", 0, conditions->getConditions().size());
        TSM_ASSERT_EQUALS("# of AudienceRestriction child elements", 0, conditions->getAudienceRestrictions().size());
        TSM_ASSERT_EQUALS("# of OneTimeUse child elements", 0, conditions->getOneTimeUses().size());
        TSM_ASSERT_EQUALS("# of ProxyRestriction child elements", 0, conditions->getProxyRestrictions().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Conditions* conditions= dynamic_cast<Conditions*>(xo.get());
        TS_ASSERT(conditions!=NULL);

        TS_ASSERT(conditions->getNotBefore()==NULL);
        TS_ASSERT(conditions->getNotOnOrAfter()==NULL);

        TSM_ASSERT_EQUALS("# of Condition child elements", 0, conditions->getConditions().size());
        TSM_ASSERT_EQUALS("# of AudienceRestriction child elements", 3, conditions->getAudienceRestrictions().size());
        TSM_ASSERT_EQUALS("# of OneTimeUse child elements", 1, conditions->getOneTimeUses().size());
        TSM_ASSERT_EQUALS("# of ProxyRestriction child elements", 2, conditions->getProxyRestrictions().size());
    }

    void testSingleElementMarshall() {
        Conditions* conditions=ConditionsBuilder::buildConditions();
        assertEquals(expectedDOM, conditions);
    }

    void testSingleElementOptionalAttributesMarshall() {
        Conditions* conditions=ConditionsBuilder::buildConditions();
        conditions->setNotBefore(expectedNotBefore);
        conditions->setNotOnOrAfter(expectedNotOnOrAfter);
        assertEquals(expectedOptionalAttributesDOM, conditions);
    }

    void testChildElementsMarshall() {
        Conditions* conditions=ConditionsBuilder::buildConditions();

        //Test storing children as their direct type 
        conditions->getAudienceRestrictions().push_back(AudienceRestrictionBuilder::buildAudienceRestriction());
        conditions->getAudienceRestrictions().push_back(AudienceRestrictionBuilder::buildAudienceRestriction());
        conditions->getProxyRestrictions().push_back(ProxyRestrictionBuilder::buildProxyRestriction());
        conditions->getAudienceRestrictions().push_back(AudienceRestrictionBuilder::buildAudienceRestriction());
        conditions->getOneTimeUses().push_back(OneTimeUseBuilder::buildOneTimeUse());
        conditions->getProxyRestrictions().push_back(ProxyRestrictionBuilder::buildProxyRestriction());
        assertEquals(expectedChildElementsDOM, conditions);

        // Note: assertEquals() above has already 'delete'-ed the XMLObject* it was passed
        conditions=NULL;
        conditions=ConditionsBuilder::buildConditions();

        //Test storing children as a Condition (each is a derived type of ConditionAbstractType)
        conditions->getConditions().push_back(AudienceRestrictionBuilder::buildAudienceRestriction());
        conditions->getConditions().push_back(AudienceRestrictionBuilder::buildAudienceRestriction());
        conditions->getConditions().push_back(ProxyRestrictionBuilder::buildProxyRestriction());
        conditions->getConditions().push_back(AudienceRestrictionBuilder::buildAudienceRestriction());
        conditions->getConditions().push_back(OneTimeUseBuilder::buildOneTimeUse());
        conditions->getConditions().push_back(ProxyRestrictionBuilder::buildProxyRestriction());
        assertEquals(expectedChildElementsDOM, conditions);
    }

};
