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

class ArtifactResponse20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedInResponseTo; 
    XMLCh* expectedVersion; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    scoped_ptr<XMLDateTime> expectedIssueInstant;

    // The payload will be an AuthnRequest in this test.
    // AuthnRequest marshaller autogenerates ID, Version and IssueInstant if they are nullptr,
    // so have to agree on something to put in the control XML
    XMLCh* authnRequestID;

public:
    void setUp() {
        expectedID = XMLString::transcode("def456"); 
        expectedInResponseTo = XMLString::transcode("abc123"); 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://sp.example.org/endpoint"); 
        expectedIssueInstant.reset(new XMLDateTime(XMLString::transcode("2006-02-21T16:40:00.000Z")));
        expectedIssueInstant->parseDateTime();

        authnRequestID = XMLString::transcode("test1"); 

        singleElementFile = data_path + "saml2/core/impl/ArtifactResponse.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/ArtifactResponseOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/ArtifactResponseChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedInResponseTo);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        XMLString::release(&authnRequestID);
        expectedIssueInstant.reset();
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        ArtifactResponse* response = dynamic_cast<ArtifactResponse*>(xo.get());
        TS_ASSERT(response!=nullptr);

        assertEquals("ID attribute", expectedID, response->getID());
        assertEquals("Version attribute", expectedVersion, response->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), response->getIssueInstant()->getEpoch());

        TS_ASSERT(response->getIssuer()==nullptr);
        TS_ASSERT(response->getSignature()==nullptr);
        TS_ASSERT(response->getExtensions()==nullptr);
        TS_ASSERT(response->getStatus()==nullptr);
        TS_ASSERT(response->getPayload()==nullptr);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        ArtifactResponse* response = dynamic_cast<ArtifactResponse*>(xo.get());
        TS_ASSERT(response!=nullptr);

        assertEquals("Consent attribute", expectedConsent, response->getConsent());
        assertEquals("Destination attribute", expectedDestination, response->getDestination());
        assertEquals("InResponseTo attribute", expectedInResponseTo, response->getInResponseTo());

        TS_ASSERT(response->getIssuer()==nullptr);
        TS_ASSERT(response->getSignature()==nullptr);
        TS_ASSERT(response->getExtensions()==nullptr);
        TS_ASSERT(response->getStatus()==nullptr);
        TS_ASSERT(response->getPayload()==nullptr);
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        ArtifactResponse* response= dynamic_cast<ArtifactResponse*>(xo.get());
        TS_ASSERT(response!=nullptr);

        TS_ASSERT(response->getIssuer()!=nullptr);
        TS_ASSERT(response->getSignature()==nullptr);
        TS_ASSERT(response->getExtensions()==nullptr);
        TS_ASSERT(response->getStatus()!=nullptr);
        TS_ASSERT(response->getPayload()!=nullptr);
    }

    void testSingleElementMarshall() {
        ArtifactResponse* response = ArtifactResponseBuilder::buildArtifactResponse();
        TS_ASSERT(response!=nullptr);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant.get());
        //response->setVersion(expectedVersion);
        assertEquals(expectedDOM, response);
    }

    void testSingleElementOptionalAttributesMarshall() {
        ArtifactResponse* response = ArtifactResponseBuilder::buildArtifactResponse();
        TS_ASSERT(response!=nullptr);

        response->setID(expectedID);
        response->setInResponseTo(expectedInResponseTo);
        response->setIssueInstant(expectedIssueInstant.get());
        //response->setVersion(expectedVersion);
        response->setConsent(expectedConsent);
        response->setDestination(expectedDestination);
        response->setInResponseTo(expectedInResponseTo);
        assertEquals(expectedOptionalAttributesDOM, response);
    }

    void testChildElementsMarshall() {
        ArtifactResponse* response = ArtifactResponseBuilder::buildArtifactResponse();
        TS_ASSERT(response!=nullptr);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant.get());
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace ns(samlconstants::SAML20_NS, samlconstants::SAML20_PREFIX);
        response->addNamespace(ns);
        response->setIssuer(IssuerBuilder::buildIssuer());
        response->setStatus(StatusBuilder::buildStatus());

        AuthnRequest* authnRequest = AuthnRequestBuilder::buildAuthnRequest();
        authnRequest->setIssueInstant(expectedIssueInstant.get());
        authnRequest->setID(authnRequestID);
        response->setPayload(authnRequest);

        assertEquals(expectedChildElementsDOM, response);
    }

};
