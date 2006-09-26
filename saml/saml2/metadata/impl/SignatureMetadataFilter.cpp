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

/**
 * SignatureMetadataFilter.cpp
 * 
 * Filters out unsigned or mis-signed elements.
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"
#include "signature/SignatureProfileValidator.h"

#include <log4cpp/Category.hh>

#include <xmltooling/util/NDC.h>
#include <xmltooling/signature/SignatureValidator.h>

using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmlsignature;
using namespace xmltooling;
using namespace log4cpp;
using namespace std;

namespace opensaml {
    namespace saml2md {
                
        class SAML_DLLLOCAL SignatureMetadataFilter : public MetadataFilter
        {
        public:
            SignatureMetadataFilter(const DOMElement* e);
            ~SignatureMetadataFilter() {
                delete m_sigValidator;
            }
            
            const char* getId() const { return SIGNATURE_METADATA_FILTER; }
            void doFilter(XMLObject& xmlObject) const;

        private:
            void doFilter(EntitiesDescriptor& entities, bool rootObject=false) const;
            void verifySignature(Signature* sig) const {
                if (sig) {
                    m_profileValidator.validate(sig);
                    m_sigValidator->validate(sig);
                }
            }
            
            SignatureProfileValidator m_profileValidator;
            SignatureValidator* m_sigValidator;
        }; 

        MetadataFilter* SAML_DLLLOCAL SignatureMetadataFilterFactory(const DOMElement* const & e)
        {
            return new SignatureMetadataFilter(e);
        }

    };
};

static const XMLCh GenericKeyResolver[] =   UNICODE_LITERAL_11(K,e,y,R,e,s,o,l,v,e,r);
static const XMLCh type[] =                 UNICODE_LITERAL_4(t,y,p,e);

SignatureMetadataFilter::SignatureMetadataFilter(const DOMElement* e) : m_sigValidator(NULL)
{
    e = XMLHelper::getFirstChildElement(e, GenericKeyResolver);
    auto_ptr_char t(e ? e->getAttributeNS(NULL,type) : NULL);
    if (t.get()) {
        auto_ptr<KeyResolver> kr(XMLToolingConfig::getConfig().KeyResolverManager.newPlugin(t.get(),e));
        m_sigValidator = new SignatureValidator(kr.get());
        kr.release();
    }
    else
        throw MetadataFilterException("missing <KeyResolver> element, or no type attribute found");
}

void SignatureMetadataFilter::doFilter(XMLObject& xmlObject) const
{
#ifdef _DEBUG
    NDC ndc("doFilter");
#endif
    
    try {
        EntitiesDescriptor& entities = dynamic_cast<EntitiesDescriptor&>(xmlObject);
        doFilter(entities, true);
        return;
    }
    catch (bad_cast) {
    }

    try {
        EntityDescriptor& entity = dynamic_cast<EntityDescriptor&>(xmlObject);
        if (!entity.getSignature())
            throw MetadataFilterException("Root metadata element was unsigned.");
        verifySignature(entity.getSignature());
    }
    catch (bad_cast) {
    }
     
    throw MetadataFilterException("SignatureMetadataFilter was given an improper metadata instance to filter.");
}

void SignatureMetadataFilter::doFilter(EntitiesDescriptor& entities, bool rootObject) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".Metadata");
    
    Signature* sig = entities.getSignature();
    if (!sig && rootObject)
        throw MetadataFilterException("Root metadata element was unsigned.");
    verifySignature(sig);
    
    VectorOf(EntityDescriptor) v=entities.getEntityDescriptors();
    for (VectorOf(EntityDescriptor)::size_type i=0; i<v.size(); ) {
        try {
            verifySignature(v[i]->getSignature());
            i++;
        }
        catch (XMLToolingException& e) {
            auto_ptr_char id(v[i]->getEntityID());
            log.info("filtering out entity (%s) after failed signature check: ", id.get(), e.what());
            v.erase(v.begin() + i);
        }
    }
    
    VectorOf(EntitiesDescriptor) w=entities.getEntitiesDescriptors();
    for (VectorOf(EntitiesDescriptor)::size_type j=0; j<w.size(); ) {
        try {
            verifySignature(w[j]->getSignature());
            j++;
        }
        catch (XMLToolingException& e) {
            auto_ptr_char name(w[j]->getName());
            log.info("filtering out group (%s) after failed signature check: ", name.get(), e.what());
            w.erase(w.begin() + j);
        }
    }
}
