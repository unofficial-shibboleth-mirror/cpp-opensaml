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

using namespace opensaml::saml2;

class AuthnStatement20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    scoped_ptr<XMLDateTime> expectedAuthnInstant;
    XMLCh* expectedSessionIndex;
    XMLDateTime* expectedSessionNotOnOrAfter;

public:
    void setUp() {
        expectedAuthnInstant.reset(new XMLDateTime(XMLString::transcode("1984-08-26T10:01:30.043Z")));
        expectedAuthnInstant->parseDateTime();
        expectedSessionIndex = (XMLString::transcode("abc123"));
        expectedSessionNotOnOrAfter = new XMLDateTime(XMLString::transcode("1984-08-26T10:11:30.043Z"));
        expectedSessionNotOnOrAfter->parseDateTime();

        singleElementFile = data_path + "saml2/core/impl/AuthnStatement.xml";
        singleElementOptionalAttributesFile = data_path + "saml2/core/impl/AuthnStatementOptionalAttributes.xml";
        childElementsFile  = data_path + "saml2/core/impl/AuthnStatementChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        expectedAuthnInstant.reset();
        XMLString::release(&expectedSessionIndex);
        delete expectedSessionNotOnOrAfter;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AuthnStatement* statement = dynamic_cast<AuthnStatement*>(xo.get());
        TS_ASSERT(statement!=nullptr);

        TSM_ASSERT_EQUALS("AuthnInstant attribute", expectedAuthnInstant->getEpoch(), statement->getAuthnInstant()->getEpoch());
        TS_ASSERT(statement->getSessionIndex()==nullptr);
        TS_ASSERT(statement->getSessionNotOnOrAfter()==nullptr);

        TS_ASSERT(statement->getSubjectLocality()==nullptr);
        TS_ASSERT(statement->getAuthnContext()==nullptr);
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        AuthnStatement* statement = dynamic_cast<AuthnStatement*>(xo.get());
        TS_ASSERT(statement!=nullptr);

        TSM_ASSERT_EQUALS("AuthnInstant attribute", expectedAuthnInstant->getEpoch(), statement->getAuthnInstant()->getEpoch());
        assertEquals("SessionIndex attribute", expectedSessionIndex, statement->getSessionIndex());
        TSM_ASSERT_EQUALS("SessionNotOnOrAfter attribute", expectedSessionNotOnOrAfter->getEpoch(), statement->getSessionNotOnOrAfter()->getEpoch());

        TS_ASSERT(statement->getSubjectLocality()==nullptr);
        TS_ASSERT(statement->getAuthnContext()==nullptr);

    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AuthnStatement* statement= dynamic_cast<AuthnStatement*>(xo.get());
        TS_ASSERT(statement!=nullptr);

        TS_ASSERT(statement->getAuthnInstant()==nullptr);
        TS_ASSERT(statement->getSessionIndex()==nullptr);
        TS_ASSERT(statement->getSessionNotOnOrAfter()==nullptr);

        TS_ASSERT(statement->getSubjectLocality()!=nullptr);
        TS_ASSERT(statement->getAuthnContext()!=nullptr);

    }

    void testSingleElementMarshall() {
        AuthnStatement* statement=AuthnStatementBuilder::buildAuthnStatement();
        statement->setAuthnInstant(expectedAuthnInstant.get());
        assertEquals(expectedDOM, statement);
    }

    void testSingleElementOptionalAttributesMarshall() {
        AuthnStatement* statement=AuthnStatementBuilder::buildAuthnStatement();
        statement->setAuthnInstant(expectedAuthnInstant.get());
        statement->setSessionIndex(expectedSessionIndex);
        statement->setSessionNotOnOrAfter(expectedSessionNotOnOrAfter);
        assertEquals(expectedOptionalAttributesDOM, statement);
    }

    void testChildElementsMarshall() {
        AuthnStatement* statement=AuthnStatementBuilder::buildAuthnStatement();
        statement->setSubjectLocality(SubjectLocalityBuilder::buildSubjectLocality());
        statement->setAuthnContext(AuthnContextBuilder::buildAuthnContext());
        assertEquals(expectedChildElementsDOM, statement);
    }

};
