/**
 * Licensed to the University Corporation for Advanced Internet
 * Development, Inc. (UCAID) under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the
 * License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

#include "internal.h"
#include <saml/saml2/core/Protocols.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2p;
using namespace opensaml::saml2;

class LogoutRequest20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedVersion; 
    DateTime* expectedIssueInstant; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    XMLCh* expectedReason; 
    DateTime* expectedNotOnOrAfter; 

public:
    void setUp() {
        expectedID = XMLString::transcode("abc123");; 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedIssueInstant = new DateTime(XMLString::transcode("2006-02-21T16:40:00.000Z"));
        expectedIssueInstant->parseDateTime();
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://idp.example.org/endpoint"); 
        expectedReason = XMLString::transcode("urn:string:reason"); 
        expectedNotOnOrAfter = new DateTime(XMLString::transcode("2006-02-21T20:45:00.000Z"));
        expectedNotOnOrAfter->parseDateTime();

        singleElementFile = data_path + "saml2/core/impl/LogoutRequest.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/LogoutRequestOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/LogoutRequestChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        XMLString::release(&expectedReason);
        delete expectedIssueInstant;
        delete expectedNotOnOrAfter;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        LogoutRequest* request = dynamic_cast<LogoutRequest*>(xo.get());
        TS_ASSERT(request!=nullptr);
        assertEquals("ID attribute", expectedID, request->getID());
        assertEquals("Version attribute", expectedVersion, request->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), request->getIssueInstant()->getEpoch());

        TS_ASSERT(request->getIssuer()==nullptr);
        TS_ASSERT(request->getSignature()==nullptr);
        TS_ASSERT(request->getExtensions()==nullptr);
        TS_ASSERT(request->getBaseID()==nullptr);
        TS_ASSERT(request->getNameID()==nullptr);
        TS_ASSERT(request->getEncryptedID()==nullptr);
        TSM_ASSERT_EQUALS("# of SessionIndex child elements", 0, request->getSessionIndexs().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        LogoutRequest* request = dynamic_cast<LogoutRequest*>(xo.get());
        TS_ASSERT(request!=nullptr);

        assertEquals("Consent attribute", expectedConsent, request->getConsent());
        assertEquals("Destination attribute", expectedDestination, request->getDestination());
        assertEquals("Reason attribute", expectedReason, request->getReason());
        TSM_ASSERT_EQUALS("NotOnOrAfter attribute", expectedNotOnOrAfter->getEpoch(), request->getNotOnOrAfter()->getEpoch());

        TS_ASSERT(request->getIssuer()==nullptr);
        TS_ASSERT(request->getSignature()==nullptr);
        TS_ASSERT(request->getExtensions()==nullptr);
        TS_ASSERT(request->getBaseID()==nullptr);
        TS_ASSERT(request->getNameID()==nullptr);
        TS_ASSERT(request->getEncryptedID()==nullptr);
        TSM_ASSERT_EQUALS("# of SessionIndex child elements", 0, request->getSessionIndexs().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        LogoutRequest* request= dynamic_cast<LogoutRequest*>(xo.get());
        TS_ASSERT(request!=nullptr);
        TS_ASSERT(request->getIssuer()!=nullptr);
        TS_ASSERT(request->getSignature()==nullptr);
        TS_ASSERT(request->getExtensions()==nullptr);
        TS_ASSERT(request->getBaseID()==nullptr);
        TS_ASSERT(request->getNameID()!=nullptr);
        TS_ASSERT(request->getEncryptedID()==nullptr);
        TSM_ASSERT_EQUALS("# of SessionIndex child elements", 2, request->getSessionIndexs().size());
    }

    void testSingleElementMarshall() {
        LogoutRequest* request=LogoutRequestBuilder::buildLogoutRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        //request->setVersion(expectedVersion);
        assertEquals(expectedDOM, request);
    }

    void testSingleElementOptionalAttributesMarshall() {
        LogoutRequest* request=LogoutRequestBuilder::buildLogoutRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        //request->setVersion(expectedVersion);
        request->setConsent(expectedConsent);
        request->setDestination(expectedDestination);
        request->setReason(expectedReason);
        request->setNotOnOrAfter(expectedNotOnOrAfter);
        assertEquals(expectedOptionalAttributesDOM, request);
    }

    void testChildElementsMarshall() {
        LogoutRequest* request=LogoutRequestBuilder::buildLogoutRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(samlconstants::SAML20_NS, samlconstants::SAML20_PREFIX);
        request->addNamespace(*ns);
        request->setIssuer(IssuerBuilder::buildIssuer());
        request->setNameID(NameIDBuilder::buildNameID());
        request->getSessionIndexs().push_back(SessionIndexBuilder::buildSessionIndex());
        request->getSessionIndexs().push_back(SessionIndexBuilder::buildSessionIndex());
        assertEquals(expectedChildElementsDOM, request);
        delete ns;
    }

};
