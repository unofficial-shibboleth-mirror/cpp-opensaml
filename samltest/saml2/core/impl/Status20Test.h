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

using namespace opensaml::saml2p;

class Status20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/Status.xml";
        childElementsFile  = data_path + "saml2/core/impl/StatusChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Status* status = dynamic_cast<Status*>(xo.get());
        TS_ASSERT(status!=nullptr);
        TSM_ASSERT("StatusCode child element", status->getStatusCode()==nullptr);
        TSM_ASSERT("StatusMessage child element", status->getStatusMessage()==nullptr);
        TSM_ASSERT("StatusDetail child element", status->getStatusDetail()==nullptr);
    }

    void testChildElementsUnmarshall() {
        scoped_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Status* status = dynamic_cast<Status*>(xo.get());
        TS_ASSERT(status!=nullptr);
        TSM_ASSERT("StatusCode child element", status->getStatusCode()!=nullptr);
        TSM_ASSERT("StatusMessage child element", status->getStatusMessage()!=nullptr);
        TSM_ASSERT("StatusDetail child element", status->getStatusDetail()!=nullptr);
    }

    void testSingleElementMarshall() {
        Status* status=StatusBuilder::buildStatus();
        assertEquals(expectedDOM, status);
    }

    void testChildElementsMarshall() {
        Status* status=StatusBuilder::buildStatus();
        status->setStatusCode(StatusCodeBuilder::buildStatusCode());
        status->setStatusMessage(StatusMessageBuilder::buildStatusMessage());
        status->setStatusDetail(StatusDetailBuilder::buildStatusDetail());
        assertEquals(expectedChildElementsDOM, status);
    }

};
