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

/**
 * WhitelistMetadataFilter.cpp
 * 
 * Removes non-whitelisted entities from a metadata instance
 */

#include "internal.h"
#include "saml2/metadata/Metadata.h"
#include "saml2/metadata/MetadataFilter.h"

#include <xmltooling/logging.h>
#include <xmltooling/util/NDC.h>

using namespace opensaml::saml2md;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

namespace opensaml {
    namespace saml2md {
                
        class SAML_DLLLOCAL WhitelistMetadataFilter : public MetadataFilter
        {
        public:
            WhitelistMetadataFilter(const DOMElement* e);
            ~WhitelistMetadataFilter() {}
            
            const char* getId() const { return WHITELIST_METADATA_FILTER; }
            void doFilter(XMLObject& xmlObject) const;

        private:
            void doFilter(EntitiesDescriptor& entities) const;
            
            bool found(const XMLCh* id) const {
                if (!id)
                    return false;
#ifdef HAVE_GOOD_STL
                return m_set.count(id)==1;
#else
                auto_ptr_char id2(id);
                return m_set.count(id2.get())==1;
#endif
            }

#ifdef HAVE_GOOD_STL
            set<xstring> m_set;
#else
            set<string> m_set;
#endif
        }; 

        MetadataFilter* SAML_DLLLOCAL WhitelistMetadataFilterFactory(const DOMElement* const & e)
        {
            return new WhitelistMetadataFilter(e);
        }

    };
};

static const XMLCh Include[] =  UNICODE_LITERAL_7(I,n,c,l,u,d,e);

WhitelistMetadataFilter::WhitelistMetadataFilter(const DOMElement* e)
{
    e = XMLHelper::getFirstChildElement(e);
    while (e) {
        if (XMLString::equals(e->getLocalName(), Include) && e->hasChildNodes()) {
#ifdef HAVE_GOOD_STL
            m_set.insert(e->getFirstChild()->getNodeValue());
#else
            auto_ptr_char id(e->getFirstChild()->getNodeValue());
            m_set.insert(id.get());
#endif
        }
        e = XMLHelper::getNextSiblingElement(e);
    }
}

void WhitelistMetadataFilter::doFilter(XMLObject& xmlObject) const
{
#ifdef _DEBUG
    NDC ndc("doFilter");
#endif
    
    try {
        doFilter(dynamic_cast<EntitiesDescriptor&>(xmlObject));
        return;
    }
    catch (bad_cast) {
    }

    try {
        EntityDescriptor& entity = dynamic_cast<EntityDescriptor&>(xmlObject);
        if (!found(entity.getEntityID()))
            throw MetadataFilterException("WhitelistMetadataFilter instructed to filter the root/only entity in the metadata.");
        return;
    }
    catch (bad_cast) {
    }
     
    throw MetadataFilterException("WhitelistMetadataFilter was given an improper metadata instance to filter.");
}

void WhitelistMetadataFilter::doFilter(EntitiesDescriptor& entities) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".Metadata");
    
    VectorOf(EntityDescriptor) v=entities.getEntityDescriptors();
    for (VectorOf(EntityDescriptor)::size_type i=0; i<v.size(); ) {
        const XMLCh* id=v[i]->getEntityID();
        if (!found(id)) {
            auto_ptr_char id2(id);
            log.info("filtering out non-whitelisted entity (%s)", id2.get());
            v.erase(v.begin() + i);
        }
        else {
            i++;
        }
    }

    const vector<EntitiesDescriptor*>& groups=const_cast<const EntitiesDescriptor&>(entities).getEntitiesDescriptors();
    for (vector<EntitiesDescriptor*>::const_iterator j=groups.begin(); j!=groups.end(); j++)
        doFilter(*(*j));
}
