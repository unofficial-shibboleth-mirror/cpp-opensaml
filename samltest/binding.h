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

#include <saml/SAMLConfig.h>
#include <saml/binding/MessageDecoder.h>
#include <saml/binding/MessageEncoder.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/security/X509TrustEngine.h>

using namespace saml2md;
using namespace xmlsignature;

class SAMLBindingBaseTestCase : public MessageDecoder::HTTPRequest
{
protected:
    CredentialResolver* m_creds; 
    MetadataProvider* m_metadata;
    opensaml::X509TrustEngine* m_trust;
    map<string,string> m_fields;

public:
    void setUp() {
        m_creds=NULL;
        m_metadata=NULL;
        m_trust=NULL;
        m_fields.clear();

        try {
            string config = data_path + "binding/ExampleMetadataProvider.xml";
            ifstream in(config.c_str());
            DOMDocument* doc=XMLToolingConfig::getConfig().getParser().parse(in);
            XercesJanitor<DOMDocument> janitor(doc);
    
            auto_ptr_XMLCh path("path");
            string s = data_path + "binding/example-metadata.xml";
            auto_ptr_XMLCh file(s.c_str());
            doc->getDocumentElement()->setAttributeNS(NULL,path.get(),file.get());
    
            m_metadata = SAMLConfig::getConfig().MetadataProviderManager.newPlugin(
                FILESYSTEM_METADATA_PROVIDER,doc->getDocumentElement()
                );
            m_metadata->init();

            config = data_path + "FilesystemCredentialResolver.xml";
            ifstream in2(config.c_str());
            DOMDocument* doc2=XMLToolingConfig::getConfig().getParser().parse(in2);
            XercesJanitor<DOMDocument> janitor2(doc2);
            m_creds = XMLToolingConfig::getConfig().CredentialResolverManager.newPlugin(
                FILESYSTEM_CREDENTIAL_RESOLVER,doc2->getDocumentElement()
                );
                
            m_trust = dynamic_cast<X509TrustEngine*>(
                SAMLConfig::getConfig().TrustEngineManager.newPlugin(EXPLICIT_KEY_SAMLTRUSTENGINE, NULL)
                );
        }
        catch (XMLToolingException& ex) {
            TS_TRACE(ex.what());
            tearDown();
            throw;
        }

    }
    
    void tearDown() {
        delete m_creds;
        delete m_metadata;
        delete m_trust;
        m_creds=NULL;
        m_metadata=NULL;
        m_trust=NULL;
        m_fields.clear();
    }

    const char* getParameter(const char* name) const {
        map<string,string>::const_iterator i=m_fields.find(name);
        return i==m_fields.end() ? NULL : i->second.c_str();
    }

    vector<const char*>::size_type getParameters(const char* name, vector<const char*>& values) const {
        values.clear();
        map<string,string>::const_iterator i=m_fields.find(name);
        if (i!=m_fields.end())
            values.push_back(i->second.c_str());
        return values.size();
    }
};
