/*
 *  Copyright 2001-2007 Internet2
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

class AttributeTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedAttributeName;
    XMLCh* expectedAttributeNamespace;

public:
    void setUp() {
        expectedAttributeName=XMLString::transcode("AttributeName");
        expectedAttributeNamespace=XMLString::transcode("namespace");
        singleElementFile = data_path + "saml1/core/impl/singleAttribute.xml";
        singleElementOptionalAttributesFile = data_path + "saml1/core/impl/singleAttributeAttributes.xml";
        childElementsFile = data_path + "saml1/core/impl/AttributeWithChildren.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedAttributeName);
        XMLString::release(&expectedAttributeNamespace);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Attribute& a = dynamic_cast<Attribute&>(*xo.get());
        TSM_ASSERT("AttributeName", a.getAttributeName()==NULL);
        TSM_ASSERT("AttributeNamespace", a.getAttributeNamespace()==NULL);
        TSM_ASSERT_EQUALS("<AttributeValue> subelement found", 0, a.getAttributeValues().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Attribute& a = dynamic_cast<Attribute&>(*xo.get());
        assertEquals("AttributeName", expectedAttributeName, a.getAttributeName());
        assertEquals("AttributeNamespace", expectedAttributeNamespace, a.getAttributeNamespace());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Attribute& a = dynamic_cast<Attribute&>(*xo.get());
        TSM_ASSERT_EQUALS("Number of <AttributeValue> subelements", 4, a.getAttributeValues().size());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AttributeBuilder::buildAttribute());
    }

    void testSingleElementOptionalAttributesMarshall() {
        Attribute* a=AttributeBuilder::buildAttribute();
        a->setAttributeName(expectedAttributeName);
        a->setAttributeNamespace(expectedAttributeNamespace);
        assertEquals(expectedOptionalAttributesDOM, a);
    }

    void testChildElementsMarshall(){
        Attribute* a=AttributeBuilder::buildAttribute();
        
        const XMLCh xsdstring[] = UNICODE_LITERAL_6(s,t,r,i,n,g);
       
        const XMLObjectBuilder* builder=XMLObjectBuilder::getBuilder(xmltooling::QName(samlconstants::SAML1_NS,AttributeValue::LOCAL_NAME));
        TS_ASSERT(builder!=NULL);
        xmltooling::QName xsitype(xmlconstants::XSD_NS,xsdstring,xmlconstants::XSD_PREFIX);
        for (int i=0; i<4; i++)
            a->getAttributeValues().push_back(builder->buildObject(samlconstants::SAML1_NS, AttributeValue::LOCAL_NAME, samlconstants::SAML1_PREFIX, &xsitype)); 

        assertEquals(expectedChildElementsDOM, a);
    }
};
