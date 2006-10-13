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

class Attribute20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedName;
    XMLCh* expectedNameFormat;
    XMLCh* expectedFriendlyName;

public:
    void setUp() {
        expectedName = XMLString::transcode("attribName");
        expectedNameFormat = XMLString::transcode("urn:string:format");
        expectedFriendlyName = XMLString::transcode("Attribute Name");

        singleElementFile = data_path + "saml2/core/impl/Attribute.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/AttributeOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/AttributeChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedName);
        XMLString::release(&expectedNameFormat);
        XMLString::release(&expectedFriendlyName);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Attribute* attribute = dynamic_cast<Attribute*>(xo.get());
        TS_ASSERT(attribute!=NULL);

        assertEquals("Name attribute", expectedName, attribute->getName());
        TS_ASSERT(attribute->getNameFormat()==NULL);
        TS_ASSERT(attribute->getFriendlyName()==NULL);

        TSM_ASSERT_EQUALS("# of AttributeValue child elements", 0, attribute->getAttributeValues().size());

    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Attribute* attribute = dynamic_cast<Attribute*>(xo.get());
        TS_ASSERT(attribute!=NULL);

        assertEquals("Name attribute", expectedName, attribute->getName());
        assertEquals("NameFormat attribute", expectedNameFormat, attribute->getNameFormat());
        assertEquals("FriendlyName attribute", expectedFriendlyName, attribute->getFriendlyName());

        TSM_ASSERT_EQUALS("# of AttributeValue child elements", 0, attribute->getAttributeValues().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Attribute* attribute= dynamic_cast<Attribute*>(xo.get());
        TS_ASSERT(attribute!=NULL);

        TS_ASSERT(attribute->getName()==NULL);
        TS_ASSERT(attribute->getNameFormat()==NULL);
        TS_ASSERT(attribute->getFriendlyName()==NULL);

        TSM_ASSERT_EQUALS("# of AttributeValue child elements", 3, attribute->getAttributeValues().size());

    }

    void testSingleElementMarshall() {
        Attribute* attribute=AttributeBuilder::buildAttribute();
        attribute->setName(expectedName);
        assertEquals(expectedDOM, attribute);
    }

    void testSingleElementOptionalAttributesMarshall() {
        Attribute* attribute=AttributeBuilder::buildAttribute();
        attribute->setName(expectedName);
        attribute->setNameFormat(expectedNameFormat);
        attribute->setFriendlyName(expectedFriendlyName);
        assertEquals(expectedOptionalAttributesDOM, attribute);
    }

    void testChildElementsMarshall() {
        Attribute* attribute=AttributeBuilder::buildAttribute();
        attribute->getAttributeValues().push_back(AttributeValueBuilder::buildAttributeValue());
        attribute->getAttributeValues().push_back(AttributeValueBuilder::buildAttributeValue());
        attribute->getAttributeValues().push_back(AttributeValueBuilder::buildAttributeValue());
        assertEquals(expectedChildElementsDOM, attribute);
    }

};
