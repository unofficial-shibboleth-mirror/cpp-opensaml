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

class ManageNameIDRequest20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedVersion; 
    DateTime* expectedIssueInstant; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 

public:
    void setUp() {
        expectedID = XMLString::transcode("abc123");; 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedIssueInstant = new DateTime(XMLString::transcode("2006-02-21T16:40:00.000Z"));
        expectedIssueInstant->parseDateTime();
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://idp.example.org/endpoint"); 

        singleElementFile = data_path + "saml2/core/impl/ManageNameIDRequest.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/ManageNameIDRequestOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/ManageNameIDRequestChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        delete expectedIssueInstant;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        ManageNameIDRequest* request = dynamic_cast<ManageNameIDRequest*>(xo.get());
        TS_ASSERT(request!=NULL);
        assertEquals("ID attribute", expectedID, request->getID());
        assertEquals("Version attribute", expectedVersion, request->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), request->getIssueInstant()->getEpoch());

        TS_ASSERT(request->getIssuer()==NULL);
        TS_ASSERT(request->getSignature()==NULL);
        TS_ASSERT(request->getExtensions()==NULL);
        TS_ASSERT(request->getNameID()==NULL);
        TS_ASSERT(request->getEncryptedID()==NULL);
        TS_ASSERT(request->getNewID()==NULL);
        TS_ASSERT(request->getNewEncryptedID()==NULL);
        TS_ASSERT(request->getTerminate()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        ManageNameIDRequest* request = dynamic_cast<ManageNameIDRequest*>(xo.get());
        TS_ASSERT(request!=NULL);

        assertEquals("Consent attribute", expectedConsent, request->getConsent());
        assertEquals("Destination attribute", expectedDestination, request->getDestination());

        TS_ASSERT(request->getIssuer()==NULL);
        TS_ASSERT(request->getSignature()==NULL);
        TS_ASSERT(request->getExtensions()==NULL);
        TS_ASSERT(request->getNameID()==NULL);
        TS_ASSERT(request->getEncryptedID()==NULL);
        TS_ASSERT(request->getNewID()==NULL);
        TS_ASSERT(request->getNewEncryptedID()==NULL);
        TS_ASSERT(request->getTerminate()==NULL);
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        ManageNameIDRequest* request= dynamic_cast<ManageNameIDRequest*>(xo.get());
        TS_ASSERT(request!=NULL);
        TS_ASSERT(request->getIssuer()!=NULL);
        TS_ASSERT(request->getSignature()==NULL);
        TS_ASSERT(request->getExtensions()==NULL);
        TS_ASSERT(request->getNameID()!=NULL);
        TS_ASSERT(request->getEncryptedID()==NULL);
        TS_ASSERT(request->getNewID()!=NULL);
        TS_ASSERT(request->getNewEncryptedID()==NULL);
        TS_ASSERT(request->getTerminate()==NULL);
    }

    void testSingleElementMarshall() {
        ManageNameIDRequest* request=ManageNameIDRequestBuilder::buildManageNameIDRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        //request->setVersion(expectedVersion);
        assertEquals(expectedDOM, request);
    }

    void testSingleElementOptionalAttributesMarshall() {
        ManageNameIDRequest* request=ManageNameIDRequestBuilder::buildManageNameIDRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        //request->setVersion(expectedVersion);
        request->setConsent(expectedConsent);
        request->setDestination(expectedDestination);
        assertEquals(expectedOptionalAttributesDOM, request);
    }

    void testChildElementsMarshall() {
        ManageNameIDRequest* request=ManageNameIDRequestBuilder::buildManageNameIDRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(opensaml::SAMLConstants::SAML20_NS, opensaml::SAMLConstants::SAML20_PREFIX);
        request->addNamespace(*ns);
        request->setIssuer(IssuerBuilder::buildIssuer());
        request->setNameID(NameIDBuilder::buildNameID());
        request->setNewID(NewIDBuilder::buildNewID());
        assertEquals(expectedChildElementsDOM, request);
        delete ns;
    }

};
