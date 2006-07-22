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

class SubjectConfirmation20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* expectedMethod; 

public:
    void setUp() {
        expectedMethod = XMLString::transcode("urn:string:cm"); 

        singleElementFile = data_path + "saml2/core/impl/SubjectConfirmation.xml";
        childElementsFile  = data_path + "saml2/core/impl/SubjectConfirmationChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&expectedMethod);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        SubjectConfirmation* sc = dynamic_cast<SubjectConfirmation*>(xo.get());
        TS_ASSERT(sc!=NULL);

        assertEquals("Method attribute", expectedMethod, sc->getMethod());

        TS_ASSERT(sc->getBaseID()==NULL);
        TS_ASSERT(sc->getNameID()==NULL);
        TS_ASSERT(sc->getEncryptedID()==NULL);
        TS_ASSERT(sc->getSubjectConfirmationData()==NULL);
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        SubjectConfirmation* sc= dynamic_cast<SubjectConfirmation*>(xo.get());
        TS_ASSERT(sc!=NULL);

        TS_ASSERT(sc->getBaseID()==NULL);
        TS_ASSERT(sc->getNameID()!=NULL);
        TS_ASSERT(sc->getEncryptedID()==NULL);
        TS_ASSERT(sc->getSubjectConfirmationData()!=NULL);
    }

    void testSingleElementMarshall() {
        SubjectConfirmation* sc=SubjectConfirmationBuilder::buildSubjectConfirmation();
        sc->setMethod(expectedMethod);
        assertEquals(expectedDOM, sc);
    }

    void testChildElementsMarshall() {
        SubjectConfirmation* sc=SubjectConfirmationBuilder::buildSubjectConfirmation();
        sc->setNameID(NameIDBuilder::buildNameID());
        sc->setSubjectConfirmationData(SubjectConfirmationDataBuilder::buildSubjectConfirmationData());
        assertEquals(expectedChildElementsDOM, sc);
    }

};
