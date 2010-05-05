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
#include <saml/saml2/core/Assertions.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2;

class AttributeStatement20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/AttributeStatement.xml";
        childElementsFile  = data_path + "saml2/core/impl/AttributeStatementChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AttributeStatement* statement = dynamic_cast<AttributeStatement*>(xo.get());
        TS_ASSERT(statement!=nullptr);

        TSM_ASSERT_EQUALS("# of Attribute child elements", 0, statement->getAttributes().size());
        TSM_ASSERT_EQUALS("# of EncryptedAttribute child elements", 0, statement->getEncryptedAttributes().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AttributeStatement* statement= dynamic_cast<AttributeStatement*>(xo.get());
        TS_ASSERT(statement!=nullptr);

        TSM_ASSERT_EQUALS("# of Attribute child elements", 3, statement->getAttributes().size());
        TSM_ASSERT_EQUALS("# of EncryptedAttribute child elements", 1, statement->getEncryptedAttributes().size());
    }

    void testSingleElementMarshall() {
        AttributeStatement* statement=AttributeStatementBuilder::buildAttributeStatement();
        assertEquals(expectedDOM, statement);
    }

    void testChildElementsMarshall() {
        AttributeStatement* statement=AttributeStatementBuilder::buildAttributeStatement();

        statement->getAttributes().push_back(AttributeBuilder::buildAttribute());
        statement->getAttributes().push_back(AttributeBuilder::buildAttribute());
        statement->getEncryptedAttributes().push_back(EncryptedAttributeBuilder::buildEncryptedAttribute());
        statement->getAttributes().push_back(AttributeBuilder::buildAttribute());
        assertEquals(expectedChildElementsDOM, statement);
    }

};
