/*
 *  Copyright 2001-2010 Internet2
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
#include <xmltooling/encryption/Encryption.h>
#include <xmltooling/util/XMLConstants.h>

using namespace opensaml;
using namespace opensaml::saml2p;
using namespace xmlencryption;

class NewEncryptedID20Test : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {

public:
    void setUp() {
        singleElementFile = data_path + "saml2/core/impl/NewEncryptedID.xml";
        childElementsFile  = data_path + "saml2/core/impl/NewEncryptedIDChildElements.xml";    
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testSingleElementUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(singleElementFile));
        NewEncryptedID* encID = dynamic_cast<NewEncryptedID*>(xo.get());
        TS_ASSERT(encID!=nullptr);
        TSM_ASSERT("EncryptedData child element", encID->getEncryptedData()==nullptr);
        TSM_ASSERT_EQUALS("# of EncryptedKey child elements", 0, encID->getEncryptedKeys().size());
    }

    void testChildElementsUnmarshall() {
        auto_ptr<XMLObject> xo(unmarshallElement(childElementsFile));
        NewEncryptedID* encID = dynamic_cast<NewEncryptedID*>(xo.get());
        TS_ASSERT(encID!=nullptr);
        TSM_ASSERT("EncryptedData child element", encID->getEncryptedData()!=nullptr);
        TSM_ASSERT_EQUALS("# of EncryptedKey child elements", 2, encID->getEncryptedKeys().size());
    }

    void testSingleElementMarshall() {
        NewEncryptedID* encID=NewEncryptedIDBuilder::buildNewEncryptedID();
        assertEquals(expectedDOM, encID);
    }

    void testChildElementsMarshall() {
        NewEncryptedID* encID=NewEncryptedIDBuilder::buildNewEncryptedID();
        // Do this just so don't have to redeclare the xenc namespace prefix on every child element in the control XML file
        Namespace* ns = new Namespace(xmlconstants::XMLENC_NS, xmlconstants::XMLENC_PREFIX);
        encID->addNamespace(*ns);
        encID->setEncryptedData(EncryptedDataBuilder::buildEncryptedData());
        encID->getEncryptedKeys().push_back(EncryptedKeyBuilder::buildEncryptedKey());
        encID->getEncryptedKeys().push_back(EncryptedKeyBuilder::buildEncryptedKey());
        assertEquals(expectedChildElementsDOM, encID);
    }

};
