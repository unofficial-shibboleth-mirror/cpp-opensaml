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
#include <saml/saml2/core/Assertions.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/signature/KeyInfo.h>

using namespace opensaml::saml2;
using xmlsignature::KeyInfoBuilder;

//TODO need testing for ElementProxy and wildcard attributes/elements

class KeyInfoConfirmationDataType20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    scoped_ptr<XMLDateTime> expectedNotBefore;
    scoped_ptr<XMLDateTime> expectedNotOnOrAfter;
    XMLCh* expectedRecipient;
    XMLCh* expectedInResponseTo;
    XMLCh* expectedAddress;

public:
    void setUp() {
        expectedNotBefore.reset(new XMLDateTime(XMLString::transcode("1984-08-26T10:01:30.043Z")));
        expectedNotBefore->parseDateTime();
        expectedNotOnOrAfter.reset(new XMLDateTime(XMLString::transcode("1984-08-26T10:11:30.043Z")));
        expectedNotOnOrAfter->parseDateTime();
        expectedRecipient = (XMLString::transcode("recipient"));
        expectedInResponseTo = (XMLString::transcode("inresponse"));
        expectedAddress = (XMLString::transcode("address"));

        singleElementFile = data_path + "saml2/core/impl/KeyInfoConfirmationDataType.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/KeyInfoConfirmationDataTypeOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/KeyInfoConfirmationDataTypeChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        expectedNotBefore.reset();
        expectedNotOnOrAfter.reset();
        XMLString::release(&expectedRecipient);
        XMLString::release(&expectedInResponseTo);
        XMLString::release(&expectedAddress);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        KeyInfoConfirmationDataType* scd = dynamic_cast<KeyInfoConfirmationDataType*>(xo.get());
        TS_ASSERT(scd!=nullptr);

        TS_ASSERT(scd->getNotBefore()==nullptr);
        TS_ASSERT(scd->getNotOnOrAfter()==nullptr);
        TS_ASSERT(scd->getRecipient()==nullptr);
        TS_ASSERT(scd->getInResponseTo()==nullptr);
        TS_ASSERT(scd->getAddress()==nullptr);
        TSM_ASSERT_EQUALS("# of KeyInfo child elements", 0, scd->getKeyInfos().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        KeyInfoConfirmationDataType* scd = dynamic_cast<KeyInfoConfirmationDataType*>(xo.get());
        TS_ASSERT(scd!=nullptr);

        TSM_ASSERT_EQUALS("NotBefore attribute", expectedNotBefore->getEpoch(), scd->getNotBefore()->getEpoch());
        TSM_ASSERT_EQUALS("NotOnOrAfter attribute", expectedNotOnOrAfter->getEpoch(), scd->getNotOnOrAfter()->getEpoch());
        assertEquals("Recipient attribute", expectedRecipient, scd->getRecipient());
        assertEquals("InResponseTo attribute", expectedInResponseTo, scd->getInResponseTo());
        assertEquals("Address attribute", expectedAddress, scd->getAddress());
        TSM_ASSERT_EQUALS("# of KeyInfo child elements", 0, scd->getKeyInfos().size());

        //TODO need to test with some wildcard attributes
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        KeyInfoConfirmationDataType* scd= dynamic_cast<KeyInfoConfirmationDataType*>(xo.get());
        TS_ASSERT(scd!=nullptr);

        TS_ASSERT(scd->getNotBefore()==nullptr);
        TS_ASSERT(scd->getNotOnOrAfter()==nullptr);
        TS_ASSERT(scd->getRecipient()==nullptr);
        TS_ASSERT(scd->getInResponseTo()==nullptr);
        TS_ASSERT(scd->getAddress()==nullptr);
        TSM_ASSERT_EQUALS("# of KeyInfo child elements", 1, scd->getKeyInfos().size());

        //TODO need to test with some wildcard child elements
    }

    void testSingleElementMarshall() {
        KeyInfoConfirmationDataType* scd=KeyInfoConfirmationDataTypeBuilder::buildKeyInfoConfirmationDataType();
        assertEquals(expectedDOM, scd);
    }

    void testSingleElementOptionalAttributesMarshall() {
        KeyInfoConfirmationDataType* scd=KeyInfoConfirmationDataTypeBuilder::buildKeyInfoConfirmationDataType();
        scd->setNotBefore(expectedNotBefore.get());
        scd->setNotOnOrAfter(expectedNotOnOrAfter.get());
        scd->setRecipient(expectedRecipient);
        scd->setInResponseTo(expectedInResponseTo);
        scd->setAddress(expectedAddress);
        //TODO need to test with some wilcard attributes
        assertEquals(expectedOptionalAttributesDOM, scd);
    }

    void testChildElementsMarshall() {
        KeyInfoConfirmationDataType* scd=KeyInfoConfirmationDataTypeBuilder::buildKeyInfoConfirmationDataType();
        scd->getKeyInfos().push_back(KeyInfoBuilder::buildKeyInfo());
        //TODO need to test with some wilcard child elements
        assertEquals(expectedChildElementsDOM, scd);
    }

};
