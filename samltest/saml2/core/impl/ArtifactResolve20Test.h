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

class ArtifactResolve20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedVersion; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    scoped_ptr<XMLDateTime> expectedIssueInstant;

public:
    void setUp() {
        expectedID = XMLString::transcode("abc123");; 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://idp.example.org/endpoint"); 
        expectedIssueInstant.reset(new XMLDateTime(XMLString::transcode("2006-02-21T16:40:00.000Z")));
        expectedIssueInstant->parseDateTime();

        singleElementFile = data_path + "saml2/core/impl/ArtifactResolve.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/ArtifactResolveOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/ArtifactResolveChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        expectedIssueInstant.reset();
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        ArtifactResolve* request = dynamic_cast<ArtifactResolve*>(xo.get());
        TS_ASSERT(request!=nullptr);
        assertEquals("ID attribute", expectedID, request->getID());
        assertEquals("Version attribute", expectedVersion, request->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), request->getIssueInstant()->getEpoch());

        TS_ASSERT(request->getIssuer()==nullptr);
        TS_ASSERT(request->getSignature()==nullptr);
        TS_ASSERT(request->getExtensions()==nullptr);
        TS_ASSERT(request->getArtifact()==nullptr);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        ArtifactResolve* request = dynamic_cast<ArtifactResolve*>(xo.get());
        TS_ASSERT(request!=nullptr);
        assertEquals("Consent attribute", expectedConsent, request->getConsent());
        assertEquals("Destination attribute", expectedDestination, request->getDestination());

        TS_ASSERT(request->getIssuer()==nullptr);
        TS_ASSERT(request->getSignature()==nullptr);
        TS_ASSERT(request->getExtensions()==nullptr);
        TS_ASSERT(request->getArtifact()==nullptr);
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        ArtifactResolve* request= dynamic_cast<ArtifactResolve*>(xo.get());
        TS_ASSERT(request!=nullptr);
        TS_ASSERT(request->getIssuer()!=nullptr);
        TS_ASSERT(request->getSignature()==nullptr);
        TS_ASSERT(request->getExtensions()==nullptr);
        TS_ASSERT(request->getArtifact()!=nullptr);
    }

    void testSingleElementMarshall() {
        ArtifactResolve* request=ArtifactResolveBuilder::buildArtifactResolve();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant.get());
        //request->setVersion(expectedVersion);
        assertEquals(expectedDOM, request);
    }

    void testSingleElementOptionalAttributesMarshall() {
        ArtifactResolve* request=ArtifactResolveBuilder::buildArtifactResolve();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant.get());
        //request->setVersion(expectedVersion);
        request->setConsent(expectedConsent);
        request->setDestination(expectedDestination);
        assertEquals(expectedOptionalAttributesDOM, request);
    }

    void testChildElementsMarshall() {
        ArtifactResolve* request=ArtifactResolveBuilder::buildArtifactResolve();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant.get());
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace ns(samlconstants::SAML20_NS, samlconstants::SAML20_PREFIX);
        request->addNamespace(ns);
        request->setIssuer(IssuerBuilder::buildIssuer());
        request->setArtifact(ArtifactBuilder::buildArtifact());
        assertEquals(expectedChildElementsDOM, request);
    }

};
