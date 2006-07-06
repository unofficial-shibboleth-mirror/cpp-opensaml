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


class Response20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedInResponseTo; 
    XMLCh* expectedVersion; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    DateTime* expectedIssueInstant; 

    // Assertion marshaller autogenerates ID, Version and IssueInstant if they are NULL,
    // so have to agree on something to put in the control XML
    XMLCh* assertionID1, * assertionID2, * assertionID3;

public:
    void setUp() {
        expectedID = XMLString::transcode("def456"); 
        expectedInResponseTo = XMLString::transcode("abc123"); 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://sp.example.org/endpoint"); 
        expectedIssueInstant = new DateTime(XMLString::transcode("2006-02-21T16:40:00.000Z"));

        assertionID1 = XMLString::transcode("test1"); 
        assertionID2= XMLString::transcode("test2"); 
        assertionID3 = XMLString::transcode("test3"); 

        singleElementFile = data_path + "saml2/core/impl/Response.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/ResponseOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/ResponseChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedInResponseTo);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        XMLString::release(&assertionID1);
        XMLString::release(&assertionID2);
        XMLString::release(&assertionID3);
        delete expectedIssueInstant;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Response* response = dynamic_cast<Response*>(xo.get());
        TS_ASSERT(response!=NULL);

        assertEquals("ID attribute", expectedID, response->getID());
        assertEquals("Version attribute", expectedVersion, response->getVersion());
        assertEquals("IssueInstant attribute", expectedIssueInstant->getFormattedString(), response->getIssueInstant()->getFormattedString());

        TS_ASSERT(response->getIssuer()==NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()==NULL);
        TSM_ASSERT_EQUALS("# of Assertion child elements", 0, response->getAssertions().size());
        TSM_ASSERT_EQUALS("# of EncryptedAssertion child elements", 0, response->getEncryptedAssertions().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        Response* response = dynamic_cast<Response*>(xo.get());
        TS_ASSERT(response!=NULL);

        assertEquals("Consent attribute", expectedConsent, response->getConsent());
        assertEquals("Destination attribute", expectedDestination, response->getDestination());
        assertEquals("InResponseTo attribute", expectedInResponseTo, response->getInResponseTo());

        TS_ASSERT(response->getIssuer()==NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()==NULL);
        TSM_ASSERT_EQUALS("# of Assertion child elements", 0, response->getAssertions().size());
        TSM_ASSERT_EQUALS("# of EncryptedAssertion child elements", 0, response->getEncryptedAssertions().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Response* response= dynamic_cast<Response*>(xo.get());
        TS_ASSERT(response!=NULL);

        TS_ASSERT(response->getIssuer()!=NULL);
        TS_ASSERT(response->getSignature()!=NULL);
        TS_ASSERT(response->getExtensions()!=NULL);
        TS_ASSERT(response->getStatus()!=NULL);
        TSM_ASSERT_EQUALS("# of Assertion child elements", 3, response->getAssertions().size());
        TSM_ASSERT_EQUALS("# of EncryptedAssertion child elements", 1, response->getEncryptedAssertions().size());
    }

    void testSingleElementMarshall() {
        Response* response = ResponseBuilder::buildResponse();
        TS_ASSERT(response!=NULL);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant);
        //response->setVersion(expectedVersion);
        assertEquals(expectedDOM, response);
    }

    void testSingleElementOptionalAttributesMarshall() {
        Response* response = ResponseBuilder::buildResponse();
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
        Response* response = ResponseBuilder::buildResponse();
        TS_ASSERT(response!=NULL);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant);
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(opensaml::SAMLConstants::SAML20_NS, opensaml::SAMLConstants::SAML20_PREFIX);
        response->addNamespace(*ns);
        response->setIssuer(IssuerBuilder::buildIssuer());
        // If the form of the default, basic, empty signature that is emittted changes wrt whitespace, etc,
        // this will probably break the test.  In that case need to fix the control XML.
        response->setSignature(xmlsignature::SignatureBuilder::buildSignature());
        response->setExtensions(ExtensionsBuilder::buildExtensions());
        response->setStatus(StatusBuilder::buildStatus());

        Assertion* assertion=NULL;

        assertion = AssertionBuilder::buildAssertion();
        assertion->setIssueInstant(expectedIssueInstant);
        assertion->setID(assertionID1);
        response->getAssertions().push_back(assertion);

        assertion = AssertionBuilder::buildAssertion();
        assertion->setIssueInstant(expectedIssueInstant);
        assertion->setID(assertionID2);
        response->getAssertions().push_back(assertion);

        response->getEncryptedAssertions().push_back((EncryptedAssertionBuilder::buildEncryptedAssertion()));

        assertion = AssertionBuilder::buildAssertion();
        assertion->setIssueInstant(expectedIssueInstant);
        assertion->setID(assertionID3);
        response->getAssertions().push_back(assertion);


        assertEquals(expectedChildElementsDOM, response);
        delete ns;
    }

};
