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

/*
   This tests building an element of type StatusResponseType with a non-SAML element name and namespace
 */

class StatusResponse20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedID; 
    XMLCh* expectedInResponseTo; 
    XMLCh* expectedVersion; 
    XMLCh* expectedConsent; 
    XMLCh* expectedDestination; 
    DateTime* expectedIssueInstant; 

    //TODO possibly move these up to SAMLObjectBaseTestCase, for use in optional helper methods below
    XMLCh* elementName;
    XMLCh* elementNS;
    XMLCh* elementPrefix;
    const XMLCh* typeName;
    const XMLCh* typeNS;
    const XMLCh* typePrefix;

public:
    void setUp() {
        expectedID = XMLString::transcode("def456"); 
        expectedInResponseTo = XMLString::transcode("abc123"); 
        expectedVersion = XMLString::transcode("2.0"); 
        expectedConsent = XMLString::transcode("urn:string:consent"); 
        expectedDestination = XMLString::transcode("http://sp.example.org/endpoint"); 
        expectedIssueInstant = new DateTime(XMLString::transcode("2006-02-21T16:40:00.000Z"));
        expectedIssueInstant->parseDateTime();

        elementName = XMLString::transcode("Foo");;
        elementNS = XMLString::transcode("http://www.example.org/test");
        elementPrefix = XMLString::transcode("test");;
        typeName = StatusResponse::TYPE_NAME;
        typeNS = SAMLConstants::SAML20P_NS;
        typePrefix = SAMLConstants::SAML20P_PREFIX;

        singleElementFile = data_path + "saml2/core/impl/StatusResponse.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/StatusResponseOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/StatusResponseChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedID);
        XMLString::release(&expectedInResponseTo);
        XMLString::release(&expectedVersion);
        XMLString::release(&expectedConsent);
        XMLString::release(&expectedDestination);
        XMLString::release(&elementName);
        XMLString::release(&elementNS);
        XMLString::release(&elementPrefix);
        delete expectedIssueInstant;
        SAMLObjectBaseTestCase::tearDown();
    }

    //TODO possibly move this functionality up to SAMLObjectBaseTestCase, as optional helper method
    void checkNameAndType(XMLObject* xo) {
        assertEquals("Element name", elementName, xo->getElementQName().getLocalPart());
        assertEquals("Element namespace", elementNS, xo->getElementQName().getNamespaceURI());
        assertEquals("Element namespace prefix", elementPrefix, xo->getElementQName().getPrefix());

        assertEquals("Schema type name", typeName, xo->getSchemaType()->getLocalPart());
        assertEquals("Schema type namespace", typeNS, xo->getSchemaType()->getNamespaceURI());
        assertEquals("Schema type namespace prefix", typePrefix, xo->getSchemaType()->getPrefix());
    }

    //TODO possibly move this functionality up to SAMLObjectBaseTestCase, as optional helper method
    XMLObject * buildObject() {
        const XMLObjectBuilder* builder = XMLObjectBuilder::getBuilder(QName(typeNS,typeName));
        QName type(typeNS,typeName,typePrefix);
        return builder->buildObject(elementNS, elementName, elementPrefix, &type);
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        StatusResponse* response = dynamic_cast<StatusResponse*>(xo.get());
        TS_ASSERT(response!=NULL);

        checkNameAndType(response);

        assertEquals("ID attribute", expectedID, response->getID());
        assertEquals("Version attribute", expectedVersion, response->getVersion());
        TSM_ASSERT_EQUALS("IssueInstant attribute", expectedIssueInstant->getEpoch(), response->getIssueInstant()->getEpoch());

        TS_ASSERT(response->getIssuer()==NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        StatusResponse* response = dynamic_cast<StatusResponse*>(xo.get());
        TS_ASSERT(response!=NULL);

        checkNameAndType(response);

        assertEquals("Consent attribute", expectedConsent, response->getConsent());
        assertEquals("Destination attribute", expectedDestination, response->getDestination());
        assertEquals("InResponseTo attribute", expectedInResponseTo, response->getInResponseTo());

        TS_ASSERT(response->getIssuer()==NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()==NULL);
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        StatusResponse* response= dynamic_cast<StatusResponse*>(xo.get());
        TS_ASSERT(response!=NULL);

        checkNameAndType(response);

        TS_ASSERT(response->getIssuer()!=NULL);
        TS_ASSERT(response->getSignature()==NULL);
        TS_ASSERT(response->getExtensions()==NULL);
        TS_ASSERT(response->getStatus()!=NULL);
    }

    void testSingleElementMarshall() {
        StatusResponse* response = dynamic_cast<StatusResponse*>(buildObject());
        TS_ASSERT(response!=NULL);
        checkNameAndType(response);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant);
        //response->setVersion(expectedVersion);
        assertEquals(expectedDOM, response);
    }

    void testSingleElementOptionalAttributesMarshall() {
        StatusResponse* response = dynamic_cast<StatusResponse*>(buildObject());
        TS_ASSERT(response!=NULL);
        checkNameAndType(response);

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
        StatusResponse* response = dynamic_cast<StatusResponse*>(buildObject());
        TS_ASSERT(response!=NULL);
        checkNameAndType(response);

        response->setID(expectedID);
        response->setIssueInstant(expectedIssueInstant);
        // Do this just so don't have to redeclare the saml namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(opensaml::SAMLConstants::SAML20_NS, opensaml::SAMLConstants::SAML20_PREFIX);
        response->addNamespace(*ns);
        response->setIssuer(IssuerBuilder::buildIssuer());
        response->setStatus(StatusBuilder::buildStatus());
        assertEquals(expectedChildElementsDOM, response);
        delete ns;
    }

};
