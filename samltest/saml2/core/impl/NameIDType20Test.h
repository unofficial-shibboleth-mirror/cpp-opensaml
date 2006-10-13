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

/*
   This tests building an element of type NameIDType with a non-SAML element name and namespace
 */

class NameIDType20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedNameQualifier; 
    XMLCh* expectedSPNameQualifier; 
    XMLCh* expectedFormat; 
    XMLCh* expectedSPProvidedID; 
    XMLCh* expectedContent; 

    //TODO possibly move these up to SAMLObjectBaseTestCase, for use in optional helper methods below
    XMLCh* elementName;
    XMLCh* elementNS;
    XMLCh* elementPrefix;
    const XMLCh* typeName;
    const XMLCh* typeNS;
    const XMLCh* typePrefix;

public:
    void setUp() {
        expectedNameQualifier = XMLString::transcode("nq"); 
        expectedSPNameQualifier = XMLString::transcode("spnq"); 
        expectedFormat = XMLString::transcode("format"); 
        expectedSPProvidedID = XMLString::transcode("spID"); 
        expectedContent = XMLString::transcode("someNameID"); 

        elementName = XMLString::transcode("Foo");;
        elementNS = XMLString::transcode("http://www.example.org/test");
        elementPrefix = XMLString::transcode("test");;
        typeName = NameIDType::TYPE_NAME;
        typeNS = SAMLConstants::SAML20_NS;
        typePrefix = SAMLConstants::SAML20_PREFIX;

        singleElementFile = data_path + "saml2/core/impl/NameIDType.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/NameIDTypeOptionalAttributes.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedNameQualifier);
        XMLString::release(&expectedSPNameQualifier);
        XMLString::release(&expectedFormat);
        XMLString::release(&expectedSPProvidedID);
        XMLString::release(&expectedContent);
        XMLString::release(&elementName);
        XMLString::release(&elementNS);
        XMLString::release(&elementPrefix);
        SAMLObjectBaseTestCase::tearDown();
    }

    //TODO possibly move this functionality up to SAMLObjectBaseTestCase, as optional helper method
    void checkNameAndType(XMLObject* xo) {
        assertEquals("Element name", elementName, xo->getElementQName().getLocalPart());
        assertEquals("Element namespace", elementNS, xo->getElementQName().getNamespaceURI());
        assertEquals("Element namespace prefix", elementPrefix, xo->getElementQName().getPrefix());

        assertEquals("Schema type name", typeName, xo->getSchemaType()->getLocalPart());
        assertEquals("Schema type namespace", typeNS, xo->getSchemaType()->getNamespaceURI());
        assertEquals("Schema type namespace prefix", typePrefix, xo->getSchemaType()->getPrefix());
    }

    //TODO possibly move this functionality up to SAMLObjectBaseTestCase, as optional helper method
    XMLObject * buildObject() {
        const XMLObjectBuilder* builder = XMLObjectBuilder::getBuilder(QName(typeNS,typeName));
        QName type(typeNS,typeName,typePrefix);
        return builder->buildObject(elementNS, elementName, elementPrefix, &type);
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        NameIDType* nameid = dynamic_cast<NameIDType*>(xo.get());
        TS_ASSERT(nameid!=NULL);

        checkNameAndType(nameid);

        assertEquals("Element content", expectedContent, nameid->getName());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        NameIDType* nameid = dynamic_cast<NameIDType*>(xo.get());
        TS_ASSERT(nameid!=NULL);

        checkNameAndType(nameid);

        assertEquals("NameQualifier attribute", expectedNameQualifier, nameid->getNameQualifier());
        assertEquals("SPNameQualifier attribute", expectedSPNameQualifier, nameid->getSPNameQualifier());
        assertEquals("Format attribute", expectedFormat, nameid->getFormat());
        assertEquals("SPProvidedID attribute", expectedSPProvidedID, nameid->getSPProvidedID());
        assertEquals("Element content", expectedContent, nameid->getName());
    }


    void testSingleElementMarshall() {
        NameIDType* nameid = dynamic_cast<NameIDType*>(buildObject());
        TS_ASSERT(nameid!=NULL);
        checkNameAndType(nameid);

        nameid->setName(expectedContent);
        assertEquals(expectedDOM, nameid);
    }

    void testSingleElementOptionalAttributesMarshall() {
        NameIDType* nameid = dynamic_cast<NameIDType*>(buildObject());
        TS_ASSERT(nameid!=NULL);
        checkNameAndType(nameid);

        nameid->setNameQualifier(expectedNameQualifier);
        nameid->setSPNameQualifier(expectedSPNameQualifier);
        nameid->setFormat(expectedFormat);
        nameid->setSPProvidedID(expectedSPProvidedID);
        nameid->setName(expectedContent);
        assertEquals(expectedOptionalAttributesDOM, nameid);
    }

};
