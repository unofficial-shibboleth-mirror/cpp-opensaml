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
#include <saml/saml1/core/Assertions.h>

using namespace opensaml::saml1;

class AuthenticationStatementTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedAuthenticationMethod;
    XMLCh* expectedAuthenticationInstant;

public:
    void setUp() {
        expectedAuthenticationInstant=XMLString::transcode("1970-01-02T01:01:02.123Z");
        expectedAuthenticationMethod=XMLString::transcode("trustme");
        singleElementFile = data_path + "saml1/core/impl/singleAuthenticationStatement.xml";
        singleElementOptionalAttributesFile = data_path + "saml1/core/impl/singleAuthenticationStatementAttributes.xml";
        childElementsFile  = data_path + "saml1/core/impl/AuthenticationStatementWithChildren.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedAuthenticationInstant);
        XMLString::release(&expectedAuthenticationMethod);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AuthenticationStatement& as = dynamic_cast<AuthenticationStatement&>(*xo.get());
        TSM_ASSERT("AuthenticationMethod attribute present", as.getAuthenticationMethod()==nullptr);
        TSM_ASSERT("AuthenticationInstant attribute present", as.getAuthenticationInstant()==nullptr);

        TSM_ASSERT("Subject element", as.getSubject()==nullptr);
        TSM_ASSERT("SubjectLocality element", as.getSubjectLocality()==nullptr);
        TSM_ASSERT_EQUALS("AuthorityBinding element count", 0, as.getAuthorityBindings().size());
    }

    void testSingleElementOptionalAttributesUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementOptionalAttributesFile));
        AuthenticationStatement& as = dynamic_cast<AuthenticationStatement&>(*xo.get());

        assertEquals("AuthenticationMethod attribute", expectedAuthenticationMethod, as.getAuthenticationMethod());
        assertEquals("AuthenticationInstant attribute", expectedAuthenticationInstant, as.getAuthenticationInstant()->getRawData());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AuthenticationStatement& as1 = dynamic_cast<AuthenticationStatement&>(*xo.get());
        as1.releaseThisAndChildrenDOM();
        auto_ptr<AuthenticationStatement> as2(as1.cloneAuthenticationStatement());
        AuthenticationStatement& as=*as2.get();

        TSM_ASSERT("Subject element", as.getSubject()!=nullptr);
        TSM_ASSERT("SubjectLocality element", as.getSubjectLocality()!=nullptr);

        TSM_ASSERT_EQUALS("AuthorityBinding element count", 2, as.getAuthorityBindings().size());
        as.getAuthorityBindings().erase(as.getAuthorityBindings().begin());
        TSM_ASSERT_EQUALS("AuthorityBinding element count", 1, as.getAuthorityBindings().size());
    }

    void testSingleElementMarshall() {
        assertEquals(expectedDOM, AuthenticationStatementBuilder::buildAuthenticationStatement());
    }

    void testSingleElementOptionalAttributesMarshall() {
        AuthenticationStatement* as=AuthenticationStatementBuilder::buildAuthenticationStatement();
        as->setAuthenticationInstant(expectedAuthenticationInstant);
        as->setAuthenticationMethod(expectedAuthenticationMethod);
        assertEquals(expectedOptionalAttributesDOM, as);
    }

    void testChildElementsMarshall() {
        AuthenticationStatement* as=AuthenticationStatementBuilder::buildAuthenticationStatement();
        as->setSubject(SubjectBuilder::buildSubject());
        as->setSubjectLocality(SubjectLocalityBuilder::buildSubjectLocality());
        as->getAuthorityBindings().push_back(AuthorityBindingBuilder::buildAuthorityBinding());
        as->getAuthorityBindings().push_back(AuthorityBindingBuilder::buildAuthorityBinding());
        assertEquals(expectedChildElementsDOM, as);
    }

};
