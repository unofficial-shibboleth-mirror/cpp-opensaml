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

class AttributeDesignatorTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedAttributeName;
    XMLCh* expectedAttributeNamespace;

public:
    void setUp() {
        expectedAttributeName=XMLString::transcode("AttributeName");
        expectedAttributeNamespace=XMLString::transcode("namespace");
        singleElementFile = data_path + "saml1/core/impl/singleAttributeDesignator.xml";
        singleElementOptionalAttributesFile = data_path + "saml1/core/impl/singleAttributeDesignatorAttributes.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedAttributeName);
        XMLString::release(&expectedAttributeNamespace);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AttributeDesignator& ad = dynamic_cast<AttributeDesignator&>(*xo.get());
        TSM_ASSERT("AttributeName", ad.getAttributeName()==NULL);
        TSM_ASSERT("AttributeNamespace", ad.getAttributeNamespace()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        AttributeDesignator& ad = dynamic_cast<AttributeDesignator&>(*xo.get());
        assertEquals("AttributeName", expectedAttributeName, ad.getAttributeName());
        assertEquals("AttributeNamespace", expectedAttributeNamespace, ad.getAttributeNamespace());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AttributeDesignatorBuilder::buildAttributeDesignator());
    }

    void testSingleElementOptionalAttributesMarshall() {
        AttributeDesignator* ad=AttributeDesignatorBuilder::buildAttributeDesignator();
        ad->setAttributeName(expectedAttributeName);
        ad->setAttributeNamespace(expectedAttributeNamespace);
        assertEquals(expectedOptionalAttributesDOM, ad);
    }

};
