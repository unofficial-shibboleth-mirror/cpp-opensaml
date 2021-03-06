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

class AuthnQuery20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedVersion; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    scoped_ptr<XMLDateTime> expectedIssueInstant;
    XMLCh* expectedSessionIndex; 

public:
    void setUp() {
        expectedID = XMLString::transcode("abc123");; 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://idp.example.org/endpoint"); 
        expectedIssueInstant.reset(new XMLDateTime(XMLString::transcode("2006-02-21T16:40:00.000Z")));
        expectedIssueInstant->parseDateTime();
        expectedSessionIndex = XMLString::transcode("session12345"); 

        singleElementFile = data_path + "saml2/core/impl/AuthnQuery.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/AuthnQueryOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/AuthnQueryChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        XMLString::release(&expectedSessionIndex);
        expectedIssueInstant.reset();
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AuthnQuery* query = dynamic_cast<AuthnQuery*>(xo.get());
        TS_ASSERT(query!=nullptr);
        assertEquals("ID attribute", expectedID, query->getID());
        assertEquals("Version attribute", expectedVersion, query->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), query->getIssueInstant()->getEpoch());

        TS_ASSERT(query->getIssuer()==nullptr);
        TS_ASSERT(query->getSignature()==nullptr);
        TS_ASSERT(query->getExtensions()==nullptr);
        TS_ASSERT(query->getSubject()==nullptr);
        TS_ASSERT(query->getRequestedAuthnContext()==nullptr);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        AuthnQuery* query = dynamic_cast<AuthnQuery*>(xo.get());
        TS_ASSERT(query!=nullptr);
        assertEquals("Consent attribute", expectedConsent, query->getConsent());
        assertEquals("Destination attribute", expectedDestination, query->getDestination());
        assertEquals("SessionIndex attribute", expectedSessionIndex, query->getSessionIndex());

        TS_ASSERT(query->getIssuer()==nullptr);
        TS_ASSERT(query->getSignature()==nullptr);
        TS_ASSERT(query->getExtensions()==nullptr);
        TS_ASSERT(query->getSubject()==nullptr);
        TS_ASSERT(query->getRequestedAuthnContext()==nullptr);
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AuthnQuery* query= dynamic_cast<AuthnQuery*>(xo.get());
        TS_ASSERT(query!=nullptr);
        TS_ASSERT(query->getIssuer()!=nullptr);
        TS_ASSERT(query->getSignature()==nullptr);
        TS_ASSERT(query->getExtensions()==nullptr);
        TS_ASSERT(query->getSubject()!=nullptr);
        TS_ASSERT(query->getRequestedAuthnContext()!=nullptr);
    }

    void testSingleElementMarshall() {
        AuthnQuery* query=AuthnQueryBuilder::buildAuthnQuery();
        query->setID(expectedID);
        query->setIssueInstant(expectedIssueInstant.get());
        //query->setVersion(expectedVersion);
        assertEquals(expectedDOM, query);
    }

    void testSingleElementOptionalAttributesMarshall() {
        AuthnQuery* query=AuthnQueryBuilder::buildAuthnQuery();
        query->setID(expectedID);
        query->setIssueInstant(expectedIssueInstant.get());
        //query->setVersion(expectedVersion);
        query->setConsent(expectedConsent);
        query->setDestination(expectedDestination);
        query->setSessionIndex(expectedSessionIndex);
        assertEquals(expectedOptionalAttributesDOM, query);
    }

    void testChildElementsMarshall() {
        AuthnQuery* query=AuthnQueryBuilder::buildAuthnQuery();
        query->setID(expectedID);
        query->setIssueInstant(expectedIssueInstant.get());
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace ns(samlconstants::SAML20_NS, samlconstants::SAML20_PREFIX);
        query->addNamespace(ns);
        query->setIssuer(IssuerBuilder::buildIssuer());
        query->setSubject(SubjectBuilder::buildSubject());
        query->setRequestedAuthnContext(RequestedAuthnContextBuilder::buildRequestedAuthnContext());
        assertEquals(expectedChildElementsDOM, query);
    }

};
