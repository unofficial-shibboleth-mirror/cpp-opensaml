/*
 *  Copyright 2001-2007 Internet2
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

class Subject20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/Subject.xml";
        childElementsFile  = data_path + "saml2/core/impl/SubjectChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        Subject* subject = dynamic_cast<Subject*>(xo.get());
        TS_ASSERT(subject!=NULL);

        TS_ASSERT(subject->getBaseID()==NULL);
        TS_ASSERT(subject->getNameID()==NULL);
        TS_ASSERT(subject->getEncryptedID()==NULL);
        TSM_ASSERT_EQUALS("# of SubjectConfirmation child elements", 0, subject->getSubjectConfirmations().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        Subject* subject= dynamic_cast<Subject*>(xo.get());
        TS_ASSERT(subject!=NULL);

        TS_ASSERT(subject->getBaseID()==NULL);
        TS_ASSERT(subject->getNameID()!=NULL);
        TS_ASSERT(subject->getEncryptedID()==NULL);
        TSM_ASSERT_EQUALS("# of SubjectConfirmation child elements", 2, subject->getSubjectConfirmations().size());
    }

    void testSingleElementMarshall() {
        Subject* subject=SubjectBuilder::buildSubject();
        assertEquals(expectedDOM, subject);
    }

    void testChildElementsMarshall() {
        Subject* subject=SubjectBuilder::buildSubject();
        subject->setNameID(NameIDBuilder::buildNameID());
        subject->getSubjectConfirmations().push_back(SubjectConfirmationBuilder::buildSubjectConfirmation());
        subject->getSubjectConfirmations().push_back(SubjectConfirmationBuilder::buildSubjectConfirmation());
        assertEquals(expectedChildElementsDOM, subject);
    }

};
