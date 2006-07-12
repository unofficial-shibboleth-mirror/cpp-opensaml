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
#include <saml/saml2/metadata/MetadataProvider.h>

using namespace opensaml::saml2md;

class FilesystemMetadataProviderTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* entityID;
    XMLCh* supportedProtocol;
    XMLCh* supportedProtocol2;
    MetadataProvider* metadataProvider;

public:
    void setUp() {
        entityID=XMLString::transcode("urn:mace:incommon:washington.edu");
        supportedProtocol=XMLString::transcode("urn:oasis:names:tc:SAML:1.1:protocol");
        supportedProtocol2=XMLString::transcode("urn:mace:shibboleth:1.0");
        
        auto_ptr_XMLCh MP("MetadataProvider");
        auto_ptr_XMLCh path("path");
        auto_ptr_XMLCh validate("validate");
        string s=data_path + "saml2/metadata/InCommon-metadata.xml";
        auto_ptr_XMLCh file(s.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().newDocument();
        XercesJanitor<DOMDocument> janitor(doc);
        DOMElement* root=doc->createElementNS(NULL,MP.get());
        root->setAttributeNS(NULL,path.get(),file.get());
        root->setAttributeNS(NULL,validate.get(),XMLConstants::XML_ZERO);
        metadataProvider = NULL;
        metadataProvider = SAMLConfig::getConfig().MetadataProviderManager.newPlugin(FILESYSTEM_METADATA_PROVIDER,root);
        metadataProvider->init();
        
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&entityID);
        XMLString::release(&supportedProtocol);
        delete metadataProvider;
        SAMLObjectBaseTestCase::tearDown();
    }

    void testEntityDescriptor() {
        Locker locker(metadataProvider);
        const EntityDescriptor* descriptor = metadataProvider->getEntityDescriptor(entityID);
        TSM_ASSERT("Retrieved entity descriptor was null", descriptor!=NULL);
        assertEquals("Entity's ID does not match requested ID", entityID, descriptor->getEntityID());
        TSM_ASSERT_EQUALS("Unexpected number of roles", 1, descriptor->getIDPSSODescriptors().size());
        TSM_ASSERT("Role lookup failed", descriptor->getIDPSSODescriptor(supportedProtocol)!=NULL);
        TSM_ASSERT("Role lookup failed", descriptor->getIDPSSODescriptor(supportedProtocol2)!=NULL);
    }

};
