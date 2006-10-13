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
#include <saml/saml2/core/Assertions.h>
#include <saml/util/SAMLConstants.h>

using namespace opensaml::saml2;

//TODO need testing for ElementProxy and wildcard attributes/elements

class SubjectConfirmationData20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    DateTime* expectedNotBefore;
    DateTime* expectedNotOnOrAfter;
    XMLCh* expectedRecipient;
    XMLCh* expectedInResponseTo;
    XMLCh* expectedAddress;

public:
    void setUp() {
        expectedNotBefore = new DateTime(XMLString::transcode("1984-08-26T10:01:30.043Z"));
        expectedNotBefore->parseDateTime();
        expectedNotOnOrAfter = new DateTime(XMLString::transcode("1984-08-26T10:11:30.043Z"));
        expectedNotOnOrAfter->parseDateTime();
        expectedRecipient = (XMLString::transcode("recipient"));
        expectedInResponseTo = (XMLString::transcode("inresponse"));
        expectedAddress = (XMLString::transcode("address"));

        singleElementFile = data_path + "saml2/core/impl/SubjectConfirmationData.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/SubjectConfirmationDataOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/SubjectConfirmationDataChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        delete expectedNotBefore;
        delete expectedNotOnOrAfter;
        XMLString::release(&expectedRecipient);
        XMLString::release(&expectedInResponseTo);
        XMLString::release(&expectedAddress);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        SubjectConfirmationData* scd = dynamic_cast<SubjectConfirmationData*>(xo.get());
        TS_ASSERT(scd!=NULL);

        TS_ASSERT(scd->getNotBefore()==NULL);
        TS_ASSERT(scd->getNotOnOrAfter()==NULL);
        TS_ASSERT(scd->getRecipient()==NULL);
        TS_ASSERT(scd->getInResponseTo()==NULL);
        TS_ASSERT(scd->getAddress()==NULL);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        SubjectConfirmationData* scd = dynamic_cast<SubjectConfirmationData*>(xo.get());
        TS_ASSERT(scd!=NULL);

        TSM_ASSERT_EQUALS("NotBefore attribute", expectedNotBefore->getEpoch(), scd->getNotBefore()->getEpoch());
        TSM_ASSERT_EQUALS("NotOnOrAfter attribute", expectedNotOnOrAfter->getEpoch(), scd->getNotOnOrAfter()->getEpoch());
        assertEquals("Recipient attribute", expectedRecipient, scd->getRecipient());
        assertEquals("InResponseTo attribute", expectedInResponseTo, scd->getInResponseTo());
        assertEquals("Address attribute", expectedAddress, scd->getAddress());

        //TODO need to test with some wildcard attributes
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        SubjectConfirmationData* scd= dynamic_cast<SubjectConfirmationData*>(xo.get());
        TS_ASSERT(scd!=NULL);

        TS_ASSERT(scd->getNotBefore()==NULL);
        TS_ASSERT(scd->getNotOnOrAfter()==NULL);
        TS_ASSERT(scd->getRecipient()==NULL);
        TS_ASSERT(scd->getInResponseTo()==NULL);
        TS_ASSERT(scd->getAddress()==NULL);

        //TODO need to test with some wildcard child elements
    }

    void testSingleElementMarshall() {
        SubjectConfirmationData* scd=SubjectConfirmationDataBuilder::buildSubjectConfirmationData();
        assertEquals(expectedDOM, scd);
    }

    void testSingleElementOptionalAttributesMarshall() {
        SubjectConfirmationData* scd=SubjectConfirmationDataBuilder::buildSubjectConfirmationData();
        scd->setNotBefore(expectedNotBefore);
        scd->setNotOnOrAfter(expectedNotOnOrAfter);
        scd->setRecipient(expectedRecipient);
        scd->setInResponseTo(expectedInResponseTo);
        scd->setAddress(expectedAddress);
        //TODO need to test with some wilcard attributes
        assertEquals(expectedOptionalAttributesDOM, scd);
    }

    void testChildElementsMarshall() {
        SubjectConfirmationData* scd=SubjectConfirmationDataBuilder::buildSubjectConfirmationData();
        //TODO need to test with some wilcard child elements
        assertEquals(expectedChildElementsDOM, scd);
    }

};
