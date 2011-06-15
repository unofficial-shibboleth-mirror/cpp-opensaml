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
#include <saml/saml1/core/Assertions.h>

using namespace opensaml::saml1;

class AudienceRestrictionConditionTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
public:
    void setUp() {
        singleElementFile = data_path + "saml1/core/impl/singleAudienceRestrictionCondition.xml";
        childElementsFile = data_path + "saml1/core/impl/AudienceRestrictionConditionWithChildren.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AudienceRestrictionCondition& a = dynamic_cast<AudienceRestrictionCondition&>(*xo.get());
        TSM_ASSERT_EQUALS("Count of child Audience elements !=0", 0, a.getAudiences().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AudienceRestrictionCondition& a = dynamic_cast<AudienceRestrictionCondition&>(*xo.get());
        TSM_ASSERT_EQUALS("Count of child Audience elements", 2, a.getAudiences().size());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AudienceRestrictionConditionBuilder::buildAudienceRestrictionCondition());
    }

    void testChildElementsMarshall(){
        AudienceRestrictionCondition* a=AudienceRestrictionConditionBuilder::buildAudienceRestrictionCondition();
        a->getAudiences().push_back(AudienceBuilder::buildAudience());
        a->getAudiences().push_back(AudienceBuilder::buildAudience());
        assertEquals(expectedChildElementsDOM, a);
    }
};
