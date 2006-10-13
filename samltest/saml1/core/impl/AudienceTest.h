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

class AudienceTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedUri;

public:
    void setUp() {
        expectedUri=XMLString::transcode("urn:oasis:names:tc:SAML:1.0:assertion");
        singleElementFile = data_path + "saml1/core/impl/singleAudience.xml";
        singleElementOptionalAttributesFile = data_path + "saml1/core/impl/singleAudienceAttributes.xml";
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedUri);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Audience& a = dynamic_cast<Audience&>(*xo.get());
        TSM_ASSERT("Uri is non-null", a.getAudienceURI()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Audience& a = dynamic_cast<Audience&>(*xo.get());
        assertEquals("Uri", expectedUri, a.getAudienceURI());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AudienceBuilder::buildAudience());
    }

    void testSingleElementOptionalAttributesMarshall() {
        Audience* a=AudienceBuilder::buildAudience();
        a->setAudienceURI(expectedUri);
        assertEquals(expectedOptionalAttributesDOM, a);
    }

};
