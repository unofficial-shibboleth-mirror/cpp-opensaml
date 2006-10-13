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

class IDPList20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/IDPList.xml";
        childElementsFile  = data_path + "saml2/core/impl/IDPListChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        IDPList* list = dynamic_cast<IDPList*>(xo.get());
        TS_ASSERT(list!=NULL);

        TS_ASSERT(list->getGetComplete()==NULL);
        TSM_ASSERT_EQUALS("# of IDPEntry child elements", 0, list->getIDPEntrys().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        IDPList* list= dynamic_cast<IDPList*>(xo.get());
        TS_ASSERT(list!=NULL);
        TS_ASSERT(list->getGetComplete()!=NULL);
        TSM_ASSERT_EQUALS("# of IDPEntry child elements", 3, list->getIDPEntrys().size());
    }

    void testSingleElementMarshall() {
        IDPList* list=IDPListBuilder::buildIDPList();
        assertEquals(expectedDOM, list);
    }

    void testChildElementsMarshall() {
        IDPList* list=IDPListBuilder::buildIDPList();
        list->getIDPEntrys().push_back(IDPEntryBuilder::buildIDPEntry());
        list->getIDPEntrys().push_back(IDPEntryBuilder::buildIDPEntry());
        list->getIDPEntrys().push_back(IDPEntryBuilder::buildIDPEntry());
        list->setGetComplete(GetCompleteBuilder::buildGetComplete());
        assertEquals(expectedChildElementsDOM, list);
    }

};
