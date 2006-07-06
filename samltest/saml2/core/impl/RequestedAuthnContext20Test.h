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
#include <saml/saml2/core/Protocols.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;

class RequestedAuthnContext20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedComparison; 

public:
    void setUp() {
        expectedComparison = XMLString::transcode("exact"); 

        singleElementFile = data_path + "saml2/core/impl/RequestedAuthnContext.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/RequestedAuthnContextOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/RequestedAuthnContextChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedComparison);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        RequestedAuthnContext* rac = dynamic_cast<RequestedAuthnContext*>(xo.get());
        TS_ASSERT(rac !=NULL);
        TS_ASSERT(rac->getComparison()==NULL);

        TSM_ASSERT_EQUALS("# of AuthnContextClassRef child elements", 0, rac->getAuthnContextClassRefs().size());
        TSM_ASSERT_EQUALS("# of AuthnContextDeclRef child elements", 0, rac->getAuthnContextDeclRefs().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        RequestedAuthnContext* rac = dynamic_cast<RequestedAuthnContext*>(xo.get());
        TS_ASSERT(rac!=NULL);
        assertEquals("Comparison attribute", expectedComparison, rac->getComparison());

        TSM_ASSERT_EQUALS("# of AuthnContextClassRef child elements", 0, rac->getAuthnContextClassRefs().size());
        TSM_ASSERT_EQUALS("# of AuthnContextDeclRef child elements", 0, rac->getAuthnContextDeclRefs().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        RequestedAuthnContext* rac = dynamic_cast<RequestedAuthnContext*>(xo.get());
        TS_ASSERT(rac !=NULL);
        TS_ASSERT(rac->getComparison()==NULL);

        TSM_ASSERT_EQUALS("# of AuthnContextClassRef child elements", 3, rac->getAuthnContextClassRefs().size());
        TSM_ASSERT_EQUALS("# of AuthnContextDeclRef child elements", 0, rac->getAuthnContextDeclRefs().size());
    }

    void testSingleElementMarshall() {
        RequestedAuthnContext* rac=RequestedAuthnContextBuilder::buildRequestedAuthnContext();
        assertEquals(expectedDOM, rac);
    }

    void testSingleElementOptionalAttributesMarshall() {
        RequestedAuthnContext* rac=RequestedAuthnContextBuilder::buildRequestedAuthnContext();
        rac->setComparison(expectedComparison);
        assertEquals(expectedOptionalAttributesDOM, rac);
    }

    void testChildElementsMarshall() {
        RequestedAuthnContext* rac=RequestedAuthnContextBuilder::buildRequestedAuthnContext();
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(opensaml::SAMLConstants::SAML20_NS, opensaml::SAMLConstants::SAML20_PREFIX);
        rac->addNamespace(*ns);
        rac->getAuthnContextClassRefs().push_back(AuthnContextClassRefBuilder::buildAuthnContextClassRef());
        rac->getAuthnContextClassRefs().push_back(AuthnContextClassRefBuilder::buildAuthnContextClassRef());
        rac->getAuthnContextClassRefs().push_back(AuthnContextClassRefBuilder::buildAuthnContextClassRef());
        assertEquals(expectedChildElementsDOM, rac);
        delete ns;
    }

};
