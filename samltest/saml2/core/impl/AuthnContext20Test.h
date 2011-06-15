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

class AuthnContext20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/AuthnContext.xml";
        childElementsFile  = data_path + "saml2/core/impl/AuthnContextChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        AuthnContext* ac = dynamic_cast<AuthnContext*>(xo.get());
        TS_ASSERT(ac!=nullptr);

        TS_ASSERT(ac->getAuthnContextClassRef()==nullptr);
        TS_ASSERT(ac->getAuthnContextDecl()==nullptr);
        TS_ASSERT(ac->getAuthnContextDeclRef()==nullptr);
        TSM_ASSERT_EQUALS("# of AuthenticatingAuthority child elements", 0, ac->getAuthenticatingAuthoritys().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        AuthnContext* ac= dynamic_cast<AuthnContext*>(xo.get());
        TS_ASSERT(ac!=nullptr);

        TS_ASSERT(ac->getAuthnContextClassRef()!=nullptr);
        TS_ASSERT(ac->getAuthnContextDecl()==nullptr);
        TS_ASSERT(ac->getAuthnContextDeclRef()!=nullptr);
        TSM_ASSERT_EQUALS("# of AuthenticatingAuthority child elements", 2, ac->getAuthenticatingAuthoritys().size());
    }

    void testSingleElementMarshall() {
        AuthnContext* ac=AuthnContextBuilder::buildAuthnContext();
        assertEquals(expectedDOM, ac);
    }

    void testChildElementsMarshall() {
        AuthnContext* ac=AuthnContextBuilder::buildAuthnContext();
        ac->setAuthnContextClassRef(AuthnContextClassRefBuilder::buildAuthnContextClassRef());
        ac->setAuthnContextDeclRef(AuthnContextDeclRefBuilder::buildAuthnContextDeclRef());
        ac->getAuthenticatingAuthoritys().push_back(AuthenticatingAuthorityBuilder::buildAuthenticatingAuthority());
        ac->getAuthenticatingAuthoritys().push_back(AuthenticatingAuthorityBuilder::buildAuthenticatingAuthority());
        assertEquals(expectedChildElementsDOM, ac);
    }

};
