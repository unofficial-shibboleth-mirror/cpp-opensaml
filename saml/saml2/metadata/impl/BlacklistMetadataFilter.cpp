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

/**
 * BlacklistMetadataFilter.cpp
 * 
 * Removes blacklisted entities from a metadata instance
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
                
        class SAML_DLLLOCAL BlacklistMetadataFilter : public MetadataFilter
        {
        public:
            BlacklistMetadataFilter(const DOMElement* e);
            ~BlacklistMetadataFilter() {}
            
            const char* getId() const { return BLACKLIST_METADATA_FILTER; }
            void doFilter(XMLObject& xmlObject) const;

        private:
            void doFilter(EntitiesDescriptor& entities) const;
            
            bool found(const XMLCh* id) const {
                if (!id)
                    return false;
                return m_set.count(id)==1;
            }

            set<xstring> m_set;
        }; 

        MetadataFilter* SAML_DLLLOCAL BlacklistMetadataFilterFactory(const DOMElement* const & e)
        {
            return new BlacklistMetadataFilter(e);
        }

    };
};

static const XMLCh Exclude[] =  UNICODE_LITERAL_7(E,x,c,l,u,d,e);

BlacklistMetadataFilter::BlacklistMetadataFilter(const DOMElement* e)
{
    e = XMLHelper::getFirstChildElement(e);
    while (e) {
        if (XMLString::equals(e->getLocalName(), Exclude) && e->hasChildNodes()) {
            m_set.insert(e->getFirstChild()->getNodeValue());
        }
        e = XMLHelper::getNextSiblingElement(e);
    }
}

void BlacklistMetadataFilter::doFilter(XMLObject& xmlObject) const
{
#ifdef _DEBUG
    NDC ndc("doFilter");
#endif
    
    try {
        EntitiesDescriptor& entities = dynamic_cast<EntitiesDescriptor&>(xmlObject);
        if (found(entities.getName()))
            throw MetadataFilterException("BlacklistMetadataFilter instructed to filter the root/only group in the metadata.");
        doFilter(entities);
        return;
    }
    catch (bad_cast) {
    }

    try {
        EntityDescriptor& entity = dynamic_cast<EntityDescriptor&>(xmlObject);
        if (found(entity.getEntityID()))
            throw MetadataFilterException("BlacklistMetadataFilter instructed to filter the root/only entity in the metadata.");
        return;
    }
    catch (bad_cast) {
    }
     
    throw MetadataFilterException("BlacklistMetadataFilter was given an improper metadata instance to filter.");
}

void BlacklistMetadataFilter::doFilter(EntitiesDescriptor& entities) const
{
    Category& log=Category::getInstance(SAML_LOGCAT".MetadataFilter.Blacklist");
    
    VectorOf(EntityDescriptor) v=entities.getEntityDescriptors();
    for (VectorOf(EntityDescriptor)::size_type i=0; i<v.size(); ) {
        const XMLCh* id=v[i]->getEntityID();
        if (found(id)) {
            auto_ptr_char id2(id);
            log.info("filtering out blacklisted entity (%s)", id2.get());
            v.erase(v.begin() + i);
        }
        else {
            i++;
        }
    }
    
    VectorOf(EntitiesDescriptor) w=entities.getEntitiesDescriptors();
    for (VectorOf(EntitiesDescriptor)::size_type j=0; j<w.size(); ) {
        const XMLCh* name=w[j]->getName();
        if (found(name)) {
            auto_ptr_char name2(name);
            log.info("filtering out blacklisted group (%s)", name2.get());
            w.erase(w.begin() + j);
        }
        else {
            doFilter(*(w[j]));
            j++;
        }
    }
}
