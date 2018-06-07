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
#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/security/SignatureTrustEngine.h>

using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace xmlsignature;

class StaticPKIXTrustEngineTest : public CxxTest::TestSuite, public SAMLObjectBaseTestCase {
public:
    void setUp() {
        SAMLObjectBaseTestCase::setUp();
    }
    
    void tearDown() {
        SAMLObjectBaseTestCase::tearDown();
    }

    void testStaticPKIXTrustEngine() {
        string config = data_path + "security/XMLMetadataProvider.xml";
        ifstream in(config.c_str());
        DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
        XercesJanitor<DOMDocument> janitor(doc);

        auto_ptr_XMLCh path("path");
        string s = data_path + "security/example-metadata.xml";
        auto_ptr_XMLCh file(s.c_str());
        doc->getDocumentElement()->setAttributeNS(nullptr,path.get(),file.get());

        // Build metadata provider.
        scoped_ptr<MetadataProvider> metadataProvider(
            opensaml::SAMLConfig::getConfig().MetadataProviderManager.newPlugin(XML_METADATA_PROVIDER,doc->getDocumentElement(), false)
            );
        try {
            metadataProvider->init();
        }
        catch (const XMLToolingException& ex) {
            TS_TRACE(ex.what());
            throw;
        }
        
        // Build trust engine.
        config = data_path + "security/StaticPKIXTrustEngine.xml";
        ifstream in2(config.c_str());
        DOMDocument* doc2=XMLToolingConfig::getConfig().getParser().parse(in2);
        XercesJanitor<DOMDocument> janitor2(doc2);
        scoped_ptr<TrustEngine> trustEngine(
            XMLToolingConfig::getConfig().TrustEngineManager.newPlugin(STATIC_PKIX_TRUSTENGINE,doc2->getDocumentElement(), false)
            );
        
        // Get signed assertion.
        config = data_path + "signature/SAML2Assertion.xml";
        ifstream in3(config.c_str());
        DOMDocument* doc3=XMLToolingConfig::getConfig().getParser().parse(in3);
        XercesJanitor<DOMDocument> janitor3(doc3);
        scoped_ptr<Assertion> assertion(dynamic_cast<Assertion*>(XMLObjectBuilder::getBuilder(doc3->getDocumentElement())->buildFromDocument(doc3)));
        janitor3.release();

        Locker locker(metadataProvider.get());
        const EntityDescriptor* descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria("https://idp.example.org")).first;
        TSM_ASSERT("Retrieved entity descriptor was null", descriptor!=nullptr);
        
        RoleDescriptor* role=descriptor->getIDPSSODescriptors().front();
        TSM_ASSERT("Role not present", role!=nullptr);
        
        Signature* sig=assertion->getSignature();
        TSM_ASSERT("Signature not present", sig!=nullptr);

        MetadataCredentialCriteria cc(*role);
        cc.setPeerName("https://idp.example.org");
        TSM_ASSERT("Signature failed to validate.", dynamic_cast<SignatureTrustEngine*>(trustEngine.get())->validate(*sig, *metadataProvider, &cc));

        descriptor = metadataProvider->getEntityDescriptor(MetadataProvider::Criteria("https://idp2.example.org")).first;
        TSM_ASSERT("Retrieved entity descriptor was null", descriptor!=nullptr);
        
        role=descriptor->getIDPSSODescriptors().front();
        TSM_ASSERT("Role not present", role!=nullptr);

        MetadataCredentialCriteria cc2(*role);
        cc2.setPeerName("https://idp2.example.org");
        TSM_ASSERT("Signature validated.", !dynamic_cast<SignatureTrustEngine*>(trustEngine.get())->validate(*sig, *metadataProvider, &cc2));
    }
};
