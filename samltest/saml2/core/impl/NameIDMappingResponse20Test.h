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

class NameIDMappingResponse20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedInResponseTo; 
    XMLCh* expectedVersion; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    DateTime* expectedIssueInstant; 

public:
    void setUp() {
        expectedID = XMLString::transcode("def456"); 
        expectedInResponseTo = XMLString::transcode("abc123"); 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://sp.example.org/endpoint"); 
        expectedIssueInstant = new DateTime(XMLString::transcode("2006-02-21T16:40:00.000Z"));
        expectedIssueInstant->parseDateTime();

        singleElementFile = data_path + "saml2/core/impl/NameIDMappingResponse.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/NameIDMappingResponseOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/NameIDMappingResponseChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedInResponseTo);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        delete expectedIssueInstant;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        NameIDMappingResponse* response = dynamic_cast<NameIDMappingResponse*>(xo.get());
        TS_ASSERT(response!=NULL);

        assertEquals("ID attribute", expectedID, response->getID());
        assertEquals("Version attribute", expectedVersion, response->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), response->getIssueInstant()->getEpoch());

        TS_ASSERT(response->getIssuer()==NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()==NULL);
        TS_ASSERT(response->getNameID()==NULL);
        TS_ASSERT(response->getEncryptedID()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        NameIDMappingResponse* response = dynamic_cast<NameIDMappingResponse*>(xo.get());
        TS_ASSERT(response!=NULL);

        assertEquals("Consent attribute", expectedConsent, response->getConsent());
        assertEquals("Destination attribute", expectedDestination, response->getDestination());
        assertEquals("InResponseTo attribute", expectedInResponseTo, response->getInResponseTo());

        TS_ASSERT(response->getIssuer()==NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()==NULL);
        TS_ASSERT(response->getNameID()==NULL);
        TS_ASSERT(response->getEncryptedID()==NULL);
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        NameIDMappingResponse* response= dynamic_cast<NameIDMappingResponse*>(xo.get());
        TS_ASSERT(response!=NULL);

        TS_ASSERT(response->getIssuer()!=NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()!=NULL);
        TS_ASSERT(response->getNameID()!=NULL);
        TS_ASSERT(response->getEncryptedID()==NULL);
    }

    void testSingleElementMarshall() {
        NameIDMappingResponse* response = NameIDMappingResponseBuilder::buildNameIDMappingResponse();
        TS_ASSERT(response!=NULL);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant);
        //response->setVersion(expectedVersion);
        assertEquals(expectedDOM, response);
    }

    void testSingleElementOptionalAttributesMarshall() {
        NameIDMappingResponse* response = NameIDMappingResponseBuilder::buildNameIDMappingResponse();
        TS_ASSERT(response!=NULL);

        response->setID(expectedID);
        response->setInResponseTo(expectedInResponseTo);
        response->setIssueInstant(expectedIssueInstant);
        //response->setVersion(expectedVersion);
        response->setConsent(expectedConsent);
        response->setDestination(expectedDestination);
        response->setInResponseTo(expectedInResponseTo);
        assertEquals(expectedOptionalAttributesDOM, response);
    }

    void testChildElementsMarshall() {
        NameIDMappingResponse* response = NameIDMappingResponseBuilder::buildNameIDMappingResponse();
        TS_ASSERT(response!=NULL);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant);
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(opensaml::SAMLConstants::SAML20_NS, opensaml::SAMLConstants::SAML20_PREFIX);
        response->addNamespace(*ns);
        response->setIssuer(IssuerBuilder::buildIssuer());
        response->setStatus(StatusBuilder::buildStatus());
        response->setNameID(NameIDBuilder::buildNameID());

        assertEquals(expectedChildElementsDOM, response);
        delete ns;
    }

};
