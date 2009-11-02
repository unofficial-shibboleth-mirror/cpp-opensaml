/*
 *  Copyright 2001-2009 Internet2
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
#include <saml/SAMLConfig.h>
#include <saml/saml2/binding/SAML2ArtifactType0004.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/security/SecurityHelper.h>

using namespace opensaml::saml2md;
using namespace opensaml::saml2p;
using namespace opensaml;

class XMLMetadataProviderTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
    XMLCh* entityID;
    XMLCh* entityID2;
    XMLCh* supportedProtocol;
    XMLCh* supportedProtocol2;

public:
    void setUp() {
        entityID=XMLString::transcode("urn:mace:incommon:washington.edu");
        entityID2=XMLString::transcode("urn:mace:incommon:rochester.edu");
        supportedProtocol=XMLString::transcode("urn:oasis:names:tc:SAML:1.1:protocol");
        supportedProtocol2=XMLString::transcode("urn:mace:shibboleth:1.0");
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        XMLString::release(&entityID);
        XMLString::release(&entityID2);
        XMLString::release(&supportedProtocol);
        XMLString::release(&supportedProtocol2);
        SAMLObjectBaseTestCase::tearDown();
    }

    void testXMLProvider() {
        string config = data_path + "saml2/metadata/XMLMetadataProvider.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);

        auto_ptr_XMLCh path("path");
        string s = data_path + "saml2/metadata/InCommon-metadata.xml";
        auto_ptr_XMLCh file(s.c_str());
        doc->getDocumentElement()->setAttributeNS(NULL,path.get(),file.get());

        auto_ptr<MetadataProvider> metadataProvider(
            SAMLConfig::getConfig().MetadataProviderManager.newPlugin(XML_METADATA_PROVIDER,doc->getDocumentElement())
            );
        try {
            metadataProvider->init();
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
        
        Locker locker(metadataProvider.get());
        const EntityDescriptor* descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria(entityID,NULL,NULL,false)).first;
        TSM_ASSERT("Retrieved entity descriptor was null", descriptor!=NULL);
        assertEquals("Entity's ID does not match requested ID", entityID, descriptor->getEntityID());
        TSM_ASSERT_EQUALS("Unexpected number of roles", 1, descriptor->getIDPSSODescriptors().size());
        TSM_ASSERT("Role lookup failed", find_if(descriptor->getIDPSSODescriptors(), isValidForProtocol(supportedProtocol))!=NULL);
        TSM_ASSERT("Role lookup failed", find_if(descriptor->getIDPSSODescriptors(), isValidForProtocol(supportedProtocol2))!=NULL);

        static const char* providerIdStr = "urn:mace:incommon:washington.edu";
        auto_ptr<SAML2ArtifactType0004> artifact(
            new SAML2ArtifactType0004(
                SecurityHelper::doHash("SHA1", providerIdStr, strlen(providerIdStr), false), 1
                )
            );
        descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria(artifact.get(),NULL,NULL,false)).first;
        TSM_ASSERT("Retrieved entity descriptor was null", descriptor!=NULL);
        assertEquals("Entity's ID does not match requested ID", entityID, descriptor->getEntityID());
    }

    void testXMLWithBlacklists() {
        string config = data_path + "saml2/metadata/XMLWithBlacklists.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);

        auto_ptr_XMLCh path("path");
        string s = data_path + "saml2/metadata/InCommon-metadata.xml";
        auto_ptr_XMLCh file(s.c_str());
        doc->getDocumentElement()->setAttributeNS(NULL,path.get(),file.get());

        auto_ptr<MetadataProvider> metadataProvider(
            SAMLConfig::getConfig().MetadataProviderManager.newPlugin(XML_METADATA_PROVIDER,doc->getDocumentElement())
            );
        try {
            metadataProvider->init();
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }

        Locker locker(metadataProvider.get());
        const EntityDescriptor* descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria(entityID,NULL,NULL,false)).first;
        TSM_ASSERT("Retrieved entity descriptor was not null", descriptor==NULL);
        descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria(entityID2,NULL,NULL,false)).first;
        TSM_ASSERT("Retrieved entity descriptor was null", descriptor!=NULL);
        assertEquals("Entity's ID does not match requested ID", entityID2, descriptor->getEntityID());
    }

    void testXMLWithWhitelists() {
        string config = data_path + "saml2/metadata/XMLWithWhitelists.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);

        auto_ptr_XMLCh path("path");
        string s = data_path + "saml2/metadata/InCommon-metadata.xml";
        auto_ptr_XMLCh file(s.c_str());
        doc->getDocumentElement()->setAttributeNS(NULL,path.get(),file.get());

        auto_ptr<MetadataProvider> metadataProvider(
            SAMLConfig::getConfig().MetadataProviderManager.newPlugin(XML_METADATA_PROVIDER,doc->getDocumentElement())
            );
        try {
            metadataProvider->init();
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }

        Locker locker(metadataProvider.get());
        const EntityDescriptor* descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria(entityID2,NULL,NULL,false)).first;
        TSM_ASSERT("Retrieved entity descriptor was not null", descriptor==NULL);
        descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria(entityID,NULL,NULL,false)).first;
        TSM_ASSERT("Retrieved entity descriptor was null", descriptor!=NULL);
        assertEquals("Entity's ID does not match requested ID", entityID, descriptor->getEntityID());
    }
};
