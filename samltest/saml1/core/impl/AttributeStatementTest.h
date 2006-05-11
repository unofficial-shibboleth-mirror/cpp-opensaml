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

class AttributeStatementTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
public:
    void setUp() {
        singleElementFile = data_path + "saml1/core/impl/singleAttributeStatement.xml";
        childElementsFile = data_path + "saml1/core/impl/AttributeStatementWithChildren.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AttributeStatement& as = dynamic_cast<AttributeStatement&>(*xo.get());
        TSM_ASSERT("<Subject> element present", as.getSubject()==NULL);
        TSM_ASSERT_EQUALS("Non zero count of <Attribute> elements", 0, as.getAttributes().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AttributeStatement& as = dynamic_cast<AttributeStatement&>(*xo.get());
        TSM_ASSERT("<Subject> element not present", as.getSubject()!=NULL);
        TSM_ASSERT_EQUALS("count of <Attribute> elements", 5, as.getAttributes().size());

        as.getAttributes().erase(as.getAttributes().begin());
        TSM_ASSERT_EQUALS("count of <Attribute> elements after single remove", 4, as.getAttributes().size());

        as.getAttributes().erase(as.getAttributes().begin());
        as.getAttributes().erase(as.getAttributes().begin()+1);
        TSM_ASSERT_EQUALS("count of <Attribute> elements after double remove", 2, as.getAttributes().size());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AttributeStatementBuilder::buildAttributeStatement());
    }

    void testChildElementsMarshall() {
        AttributeStatement* as=AttributeStatementBuilder::buildAttributeStatement();
        as->setSubject(SubjectBuilder::buildSubject());
        for (int i = 0; i < 5; i++) {
            as->getAttributes().push_back(AttributeBuilder::buildAttribute());
        }

        assertEquals(expectedChildElementsDOM, as);
    }

};
