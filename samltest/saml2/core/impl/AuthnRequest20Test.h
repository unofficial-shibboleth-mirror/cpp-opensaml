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

class AuthnRequest20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedVersion; 
    DateTime* expectedIssueInstant; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    bool expectedForceAuthn; 
    bool expectedIsPassive; 
    XMLCh* expectedProtocolBinding; 
    int expectedAssertionConsumerServiceIndex;
    XMLCh* expectedAssertionConsumerServiceURL; 
    int expectedAttributeConsumingServiceIndex;
    XMLCh* expectedProviderName;

public:
    void setUp() {
        expectedID = XMLString::transcode("abc123");; 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedIssueInstant = new DateTime(XMLString::transcode("2006-02-21T16:40:00.000Z"));
        expectedIssueInstant->parseDateTime();
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://idp.example.org/endpoint"); 
        expectedForceAuthn = true;
        expectedIsPassive = true;
        expectedProtocolBinding = XMLString::transcode("urn:string:protocol-binding");
        expectedAssertionConsumerServiceIndex = 3;
        expectedAssertionConsumerServiceURL = XMLString::transcode("http://sp.example.org/acs");
        expectedAttributeConsumingServiceIndex = 2;
        expectedProviderName = XMLString::transcode("Example Org");

        singleElementFile = data_path + "saml2/core/impl/AuthnRequest.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/AuthnRequestOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/AuthnRequestChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        XMLString::release(&expectedProtocolBinding);
        XMLString::release(&expectedAssertionConsumerServiceURL);
        XMLString::release(&expectedProviderName);
        delete expectedIssueInstant;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AuthnRequest* request = dynamic_cast<AuthnRequest*>(xo.get());
        TS_ASSERT(request!=NULL);
        assertEquals("ID attribute", expectedID, request->getID());
        assertEquals("Version attribute", expectedVersion, request->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), request->getIssueInstant()->getEpoch());
        TSM_ASSERT_EQUALS("ForceAuthn attribute presence", XMLConstants::XML_BOOL_NULL, request->getForceAuthn());
        TSM_ASSERT_EQUALS("IsPassive attribute presence", XMLConstants::XML_BOOL_NULL, request->getIsPassive());
        TSM_ASSERT_EQUALS("AssertionConsumerServiceIndex attribute presence",false, request->getAssertionConsumerServiceIndex().first);
        TSM_ASSERT_EQUALS("AttributeConsumingServiceIndex attribute presence", false, request->getAttributeConsumingServiceIndex().first);

        TS_ASSERT(request->getIssuer()==NULL);
        TS_ASSERT(request->getSignature()==NULL);
        TS_ASSERT(request->getExtensions()==NULL);
        TS_ASSERT(request->getSubject()==NULL);
        TS_ASSERT(request->getNameIDPolicy()==NULL);
        TS_ASSERT(request->getConditions()==NULL);
        TS_ASSERT(request->getRequestedAuthnContext()==NULL);
        TS_ASSERT(request->getScoping()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        AuthnRequest* request = dynamic_cast<AuthnRequest*>(xo.get());
        TS_ASSERT(request!=NULL);

        assertEquals("Consent attribute", expectedConsent, request->getConsent());
        assertEquals("Destination attribute", expectedDestination, request->getDestination());
        TSM_ASSERT_EQUALS("ForceAuthn attribute value", expectedForceAuthn, request->ForceAuthn());
        TSM_ASSERT_EQUALS("IsPassive attribute value", expectedIsPassive, request->IsPassive());
        assertEquals("ProtocolBinding attribute", expectedProtocolBinding,request->getProtocolBinding());
        TSM_ASSERT_EQUALS("AssertionConsumerServiceIndex attribute presence",true, request->getAssertionConsumerServiceIndex().first);
        TSM_ASSERT_EQUALS("AssertionConsumerServiceIndex attribute value",expectedAssertionConsumerServiceIndex, request->getAssertionConsumerServiceIndex().second);
        assertEquals("AssertionConsumerServierURL attribute", expectedAssertionConsumerServiceURL, request->getAssertionConsumerServiceURL());
        TSM_ASSERT_EQUALS("AttributeConsumingServiceIndex attribute presence", true, request->getAttributeConsumingServiceIndex().first);
        TSM_ASSERT_EQUALS("AttributeConsumingServiceIndex attribute value", expectedAttributeConsumingServiceIndex, request->getAttributeConsumingServiceIndex().second);
        assertEquals("ProviderName attribute", expectedProviderName, request->getProviderName());

        TS_ASSERT(request->getIssuer()==NULL);
        TS_ASSERT(request->getSignature()==NULL);
        TS_ASSERT(request->getExtensions()==NULL);
        TS_ASSERT(request->getSubject()==NULL);
        TS_ASSERT(request->getNameIDPolicy()==NULL);
        TS_ASSERT(request->getConditions()==NULL);
        TS_ASSERT(request->getRequestedAuthnContext()==NULL);
        TS_ASSERT(request->getScoping()==NULL);
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AuthnRequest* request= dynamic_cast<AuthnRequest*>(xo.get());
        TS_ASSERT(request!=NULL);
        TS_ASSERT(request->getIssuer()!=NULL);
        TS_ASSERT(request->getSignature()==NULL);
        TS_ASSERT(request->getExtensions()==NULL);
        TS_ASSERT(request->getSubject()!=NULL);
        TS_ASSERT(request->getNameIDPolicy()!=NULL);
        TS_ASSERT(request->getConditions()!=NULL);
        TS_ASSERT(request->getRequestedAuthnContext()!=NULL);
        TS_ASSERT(request->getScoping()!=NULL);
        TSM_ASSERT_EQUALS("ForceAuthn attribute presence", XMLConstants::XML_BOOL_NULL, request->getForceAuthn());
        TSM_ASSERT_EQUALS("IsPassive attribute presence", XMLConstants::XML_BOOL_NULL, request->getIsPassive());
        TSM_ASSERT_EQUALS("AssertionConsumerServiceIndex attribute presence",false, request->getAssertionConsumerServiceIndex().first);
        TSM_ASSERT_EQUALS("AttributeConsumingServiceIndex attribute presence", false, request->getAttributeConsumingServiceIndex().first);
    }

    void testSingleElementMarshall() {
        AuthnRequest* request=AuthnRequestBuilder::buildAuthnRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        //request->setVersion(expectedVersion);
        assertEquals(expectedDOM, request);
    }

    void testSingleElementOptionalAttributesMarshall() {
        AuthnRequest* request=AuthnRequestBuilder::buildAuthnRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        //request->setVersion(expectedVersion);
        request->setConsent(expectedConsent);
        request->setDestination(expectedDestination);
        request->ForceAuthn(expectedForceAuthn);
        request->IsPassive(expectedIsPassive);
        request->setProtocolBinding(expectedProtocolBinding);
        request->setAssertionConsumerServiceIndex(expectedAssertionConsumerServiceIndex);
        request->setAssertionConsumerServiceURL(expectedAssertionConsumerServiceURL);
        request->setAttributeConsumingServiceIndex(expectedAttributeConsumingServiceIndex);
        request->setProviderName(expectedProviderName);
        assertEquals(expectedOptionalAttributesDOM, request);
    }

    void testChildElementsMarshall() {
        AuthnRequest* request=AuthnRequestBuilder::buildAuthnRequest();
        request->setID(expectedID);
        request->setIssueInstant(expectedIssueInstant);
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(opensaml::SAMLConstants::SAML20_NS, opensaml::SAMLConstants::SAML20_PREFIX);
        request->addNamespace(*ns);
        request->setIssuer(IssuerBuilder::buildIssuer());
        request->setSubject(SubjectBuilder::buildSubject());
        request->setNameIDPolicy(NameIDPolicyBuilder::buildNameIDPolicy());
        request->setConditions(ConditionsBuilder::buildConditions());
        request->setRequestedAuthnContext(RequestedAuthnContextBuilder::buildRequestedAuthnContext());
        request->setScoping(ScopingBuilder::buildScoping());
        assertEquals(expectedChildElementsDOM, request);
        delete ns;
    }

};
